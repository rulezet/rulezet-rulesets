rule TTP_XOR_WriteProcessMemory_a2c2 {
  strings:
    $key_a2c2 = { f5 b0 [2] c7 92 [2] c1 a7 [2] ef a7 [2] d0 bb }

  condition:
    any of them
}