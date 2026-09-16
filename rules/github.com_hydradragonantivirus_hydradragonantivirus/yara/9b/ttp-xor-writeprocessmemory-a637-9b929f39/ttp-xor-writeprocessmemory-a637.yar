rule TTP_XOR_WriteProcessMemory_a637 {
  strings:
    $key_a637 = { f1 45 [2] c3 67 [2] c5 52 [2] eb 52 [2] d4 4e }

  condition:
    any of them
}