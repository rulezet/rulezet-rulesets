rule TTP_XOR_WriteProcessMemory_a2e6 {
  strings:
    $key_a2e6 = { f5 94 [2] c7 b6 [2] c1 83 [2] ef 83 [2] d0 9f }

  condition:
    any of them
}