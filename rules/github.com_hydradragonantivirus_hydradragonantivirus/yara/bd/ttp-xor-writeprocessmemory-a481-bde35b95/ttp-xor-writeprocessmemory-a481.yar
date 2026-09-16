rule TTP_XOR_WriteProcessMemory_a481 {
  strings:
    $key_a481 = { f3 f3 [2] c1 d1 [2] c7 e4 [2] e9 e4 [2] d6 f8 }

  condition:
    any of them
}