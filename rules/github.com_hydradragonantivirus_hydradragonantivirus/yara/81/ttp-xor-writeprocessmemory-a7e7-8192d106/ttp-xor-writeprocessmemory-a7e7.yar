rule TTP_XOR_WriteProcessMemory_a7e7 {
  strings:
    $key_a7e7 = { f0 95 [2] c2 b7 [2] c4 82 [2] ea 82 [2] d5 9e }

  condition:
    any of them
}