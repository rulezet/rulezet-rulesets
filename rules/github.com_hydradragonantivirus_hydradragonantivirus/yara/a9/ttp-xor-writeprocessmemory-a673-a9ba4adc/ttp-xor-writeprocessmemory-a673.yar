rule TTP_XOR_WriteProcessMemory_a673 {
  strings:
    $key_a673 = { f1 01 [2] c3 23 [2] c5 16 [2] eb 16 [2] d4 0a }

  condition:
    any of them
}