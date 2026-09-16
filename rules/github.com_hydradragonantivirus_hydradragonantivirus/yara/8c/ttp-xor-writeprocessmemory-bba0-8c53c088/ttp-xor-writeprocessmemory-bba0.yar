rule TTP_XOR_WriteProcessMemory_bba0 {
  strings:
    $key_bba0 = { ec d2 [2] de f0 [2] d8 c5 [2] f6 c5 [2] c9 d9 }

  condition:
    any of them
}