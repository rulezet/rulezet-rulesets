rule TTP_XOR_WriteProcessMemory_a780 {
  strings:
    $key_a780 = { f0 f2 [2] c2 d0 [2] c4 e5 [2] ea e5 [2] d5 f9 }

  condition:
    any of them
}