rule TTP_XOR_WriteProcessMemory_a600 {
  strings:
    $key_a600 = { f1 72 [2] c3 50 [2] c5 65 [2] eb 65 [2] d4 79 }

  condition:
    any of them
}