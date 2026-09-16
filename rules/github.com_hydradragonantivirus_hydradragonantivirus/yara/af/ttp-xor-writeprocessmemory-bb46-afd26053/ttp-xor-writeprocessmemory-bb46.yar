rule TTP_XOR_WriteProcessMemory_bb46 {
  strings:
    $key_bb46 = { ec 34 [2] de 16 [2] d8 23 [2] f6 23 [2] c9 3f }

  condition:
    any of them
}