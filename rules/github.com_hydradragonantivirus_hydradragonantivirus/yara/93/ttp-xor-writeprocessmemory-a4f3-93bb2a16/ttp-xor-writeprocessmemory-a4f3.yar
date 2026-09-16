rule TTP_XOR_WriteProcessMemory_a4f3 {
  strings:
    $key_a4f3 = { f3 81 [2] c1 a3 [2] c7 96 [2] e9 96 [2] d6 8a }

  condition:
    any of them
}