rule TTP_XOR_WriteProcessMemory_a384 {
  strings:
    $key_a384 = { f4 f6 [2] c6 d4 [2] c0 e1 [2] ee e1 [2] d1 fd }

  condition:
    any of them
}