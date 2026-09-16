rule TTP_XOR_WriteProcessMemory_a4e7 {
  strings:
    $key_a4e7 = { f3 95 [2] c1 b7 [2] c7 82 [2] e9 82 [2] d6 9e }

  condition:
    any of them
}