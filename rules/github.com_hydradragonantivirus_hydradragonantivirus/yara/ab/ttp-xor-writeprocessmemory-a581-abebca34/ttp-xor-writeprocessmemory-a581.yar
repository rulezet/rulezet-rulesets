rule TTP_XOR_WriteProcessMemory_a581 {
  strings:
    $key_a581 = { f2 f3 [2] c0 d1 [2] c6 e4 [2] e8 e4 [2] d7 f8 }

  condition:
    any of them
}