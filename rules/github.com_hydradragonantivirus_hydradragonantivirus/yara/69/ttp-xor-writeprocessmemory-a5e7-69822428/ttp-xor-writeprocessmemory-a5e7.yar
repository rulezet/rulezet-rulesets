rule TTP_XOR_WriteProcessMemory_a5e7 {
  strings:
    $key_a5e7 = { f2 95 [2] c0 b7 [2] c6 82 [2] e8 82 [2] d7 9e }

  condition:
    any of them
}