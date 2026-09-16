rule TTP_XOR_WriteProcessMemory_bba4 {
  strings:
    $key_bba4 = { ec d6 [2] de f4 [2] d8 c1 [2] f6 c1 [2] c9 dd }

  condition:
    any of them
}