rule TTP_XOR_WriteProcessMemory_a4d4 {
  strings:
    $key_a4d4 = { f3 a6 [2] c1 84 [2] c7 b1 [2] e9 b1 [2] d6 ad }

  condition:
    any of them
}