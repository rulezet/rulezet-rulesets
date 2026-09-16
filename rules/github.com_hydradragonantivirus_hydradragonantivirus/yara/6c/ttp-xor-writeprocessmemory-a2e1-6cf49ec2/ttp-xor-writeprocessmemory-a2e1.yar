rule TTP_XOR_WriteProcessMemory_a2e1 {
  strings:
    $key_a2e1 = { f5 93 [2] c7 b1 [2] c1 84 [2] ef 84 [2] d0 98 }

  condition:
    any of them
}