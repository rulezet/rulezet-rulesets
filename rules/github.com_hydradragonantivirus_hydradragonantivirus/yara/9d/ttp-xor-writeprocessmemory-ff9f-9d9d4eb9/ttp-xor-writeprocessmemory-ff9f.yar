rule TTP_XOR_WriteProcessMemory_ff9f {
  strings:
    $key_ff9f = { a8 ed [2] 9a cf [2] 9c fa [2] b2 fa [2] 8d e6 }

  condition:
    any of them
}