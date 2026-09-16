rule TTP_XOR_WriteProcessMemory_1f9f {
  strings:
    $key_1f9f = { 48 ed [2] 7a cf [2] 7c fa [2] 52 fa [2] 6d e6 }

  condition:
    any of them
}