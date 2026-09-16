rule TTP_XOR_WriteProcessMemory_a4d6 {
  strings:
    $key_a4d6 = { f3 a4 [2] c1 86 [2] c7 b3 [2] e9 b3 [2] d6 af }

  condition:
    any of them
}