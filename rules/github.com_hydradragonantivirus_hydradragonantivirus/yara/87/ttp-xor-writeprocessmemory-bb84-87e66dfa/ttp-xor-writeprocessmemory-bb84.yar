rule TTP_XOR_WriteProcessMemory_bb84 {
  strings:
    $key_bb84 = { ec f6 [2] de d4 [2] d8 e1 [2] f6 e1 [2] c9 fd }

  condition:
    any of them
}