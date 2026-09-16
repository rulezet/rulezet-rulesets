rule TTP_XOR_WriteProcessMemory_aa80 {
  strings:
    $key_aa80 = { fd f2 [2] cf d0 [2] c9 e5 [2] e7 e5 [2] d8 f9 }

  condition:
    any of them
}