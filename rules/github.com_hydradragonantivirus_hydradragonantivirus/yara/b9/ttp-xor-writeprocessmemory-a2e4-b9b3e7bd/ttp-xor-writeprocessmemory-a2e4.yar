rule TTP_XOR_WriteProcessMemory_a2e4 {
  strings:
    $key_a2e4 = { f5 96 [2] c7 b4 [2] c1 81 [2] ef 81 [2] d0 9d }

  condition:
    any of them
}