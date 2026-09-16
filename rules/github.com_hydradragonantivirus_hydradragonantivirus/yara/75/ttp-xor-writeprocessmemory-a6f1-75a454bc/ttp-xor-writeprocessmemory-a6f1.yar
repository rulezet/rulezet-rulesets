rule TTP_XOR_WriteProcessMemory_a6f1 {
  strings:
    $key_a6f1 = { f1 83 [2] c3 a1 [2] c5 94 [2] eb 94 [2] d4 88 }

  condition:
    any of them
}