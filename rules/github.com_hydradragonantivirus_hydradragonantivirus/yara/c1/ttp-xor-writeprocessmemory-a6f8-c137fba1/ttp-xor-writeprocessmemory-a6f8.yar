rule TTP_XOR_WriteProcessMemory_a6f8 {
  strings:
    $key_a6f8 = { f1 8a [2] c3 a8 [2] c5 9d [2] eb 9d [2] d4 81 }

  condition:
    any of them
}