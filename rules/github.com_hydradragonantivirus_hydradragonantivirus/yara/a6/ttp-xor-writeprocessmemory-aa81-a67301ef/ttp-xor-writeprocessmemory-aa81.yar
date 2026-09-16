rule TTP_XOR_WriteProcessMemory_aa81 {
  strings:
    $key_aa81 = { fd f3 [2] cf d1 [2] c9 e4 [2] e7 e4 [2] d8 f8 }

  condition:
    any of them
}