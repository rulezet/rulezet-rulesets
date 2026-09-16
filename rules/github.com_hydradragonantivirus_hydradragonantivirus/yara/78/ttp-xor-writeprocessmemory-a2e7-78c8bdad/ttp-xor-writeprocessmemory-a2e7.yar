rule TTP_XOR_WriteProcessMemory_a2e7 {
  strings:
    $key_a2e7 = { f5 95 [2] c7 b7 [2] c1 82 [2] ef 82 [2] d0 9e }

  condition:
    any of them
}