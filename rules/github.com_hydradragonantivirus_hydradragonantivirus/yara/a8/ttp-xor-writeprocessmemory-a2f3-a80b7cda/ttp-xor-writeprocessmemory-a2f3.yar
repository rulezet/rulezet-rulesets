rule TTP_XOR_WriteProcessMemory_a2f3 {
  strings:
    $key_a2f3 = { f5 81 [2] c7 a3 [2] c1 96 [2] ef 96 [2] d0 8a }

  condition:
    any of them
}