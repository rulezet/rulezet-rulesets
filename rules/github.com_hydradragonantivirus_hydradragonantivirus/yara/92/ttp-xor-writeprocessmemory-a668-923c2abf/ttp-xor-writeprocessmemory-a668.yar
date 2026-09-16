rule TTP_XOR_WriteProcessMemory_a668 {
  strings:
    $key_a668 = { f1 1a [2] c3 38 [2] c5 0d [2] eb 0d [2] d4 11 }

  condition:
    any of them
}