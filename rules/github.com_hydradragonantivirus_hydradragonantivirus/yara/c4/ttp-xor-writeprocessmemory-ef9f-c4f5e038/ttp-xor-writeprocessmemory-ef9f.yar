rule TTP_XOR_WriteProcessMemory_ef9f {
  strings:
    $key_ef9f = { b8 ed [2] 8a cf [2] 8c fa [2] a2 fa [2] 9d e6 }

  condition:
    any of them
}