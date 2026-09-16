rule TTP_XOR_WriteProcessMemory_a627 {
  strings:
    $key_a627 = { f1 55 [2] c3 77 [2] c5 42 [2] eb 42 [2] d4 5e }

  condition:
    any of them
}