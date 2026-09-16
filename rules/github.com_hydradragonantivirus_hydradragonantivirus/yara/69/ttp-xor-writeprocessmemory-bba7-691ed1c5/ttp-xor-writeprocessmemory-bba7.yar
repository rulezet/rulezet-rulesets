rule TTP_XOR_WriteProcessMemory_bba7 {
  strings:
    $key_bba7 = { ec d5 [2] de f7 [2] d8 c2 [2] f6 c2 [2] c9 de }

  condition:
    any of them
}