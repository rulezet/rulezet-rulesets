rule TTP_XOR_WriteProcessMemory_a2f6 {
  strings:
    $key_a2f6 = { f5 84 [2] c7 a6 [2] c1 93 [2] ef 93 [2] d0 8f }

  condition:
    any of them
}