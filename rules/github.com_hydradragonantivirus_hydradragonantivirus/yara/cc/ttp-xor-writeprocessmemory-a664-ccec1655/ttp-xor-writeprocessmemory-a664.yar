rule TTP_XOR_WriteProcessMemory_a664 {
  strings:
    $key_a664 = { f1 16 [2] c3 34 [2] c5 01 [2] eb 01 [2] d4 1d }

  condition:
    any of them
}