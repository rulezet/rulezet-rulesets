rule TTP_XOR_WriteProcessMemory_6f9f {
  strings:
    $key_6f9f = { 38 ed [2] 0a cf [2] 0c fa [2] 22 fa [2] 1d e6 }

  condition:
    any of them
}