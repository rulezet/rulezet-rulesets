rule TTP_XOR_WriteProcessMemory_a630 {
  strings:
    $key_a630 = { f1 42 [2] c3 60 [2] c5 55 [2] eb 55 [2] d4 49 }

  condition:
    any of them
}