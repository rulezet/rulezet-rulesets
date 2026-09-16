rule TTP_XOR_WriteProcessMemory_a272 {
  strings:
    $key_a272 = { f5 00 [2] c7 22 [2] c1 17 [2] ef 17 [2] d0 0b }

  condition:
    any of them
}