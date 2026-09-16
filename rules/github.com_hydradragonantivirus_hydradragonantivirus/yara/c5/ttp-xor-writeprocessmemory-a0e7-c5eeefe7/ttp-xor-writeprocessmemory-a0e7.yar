rule TTP_XOR_WriteProcessMemory_a0e7 {
  strings:
    $key_a0e7 = { f7 95 [2] c5 b7 [2] c3 82 [2] ed 82 [2] d2 9e }

  condition:
    any of them
}