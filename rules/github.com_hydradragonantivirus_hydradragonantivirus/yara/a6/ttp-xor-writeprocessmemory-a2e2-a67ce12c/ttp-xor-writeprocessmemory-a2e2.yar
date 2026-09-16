rule TTP_XOR_WriteProcessMemory_a2e2 {
  strings:
    $key_a2e2 = { f5 90 [2] c7 b2 [2] c1 87 [2] ef 87 [2] d0 9b }

  condition:
    any of them
}