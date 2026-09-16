rule TTP_XOR_WriteProcessMemory_bb9f {
  strings:
    $key_bb9f = { ec ed [2] de cf [2] d8 fa [2] f6 fa [2] c9 e6 }

  condition:
    any of them
}