rule TTP_XOR_WriteProcessMemory_a4f6 {
  strings:
    $key_a4f6 = { f3 84 [2] c1 a6 [2] c7 93 [2] e9 93 [2] d6 8f }

  condition:
    any of them
}