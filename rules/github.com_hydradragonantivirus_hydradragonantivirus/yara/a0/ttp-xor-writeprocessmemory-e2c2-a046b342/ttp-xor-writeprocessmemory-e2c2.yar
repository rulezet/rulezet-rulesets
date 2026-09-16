rule TTP_XOR_WriteProcessMemory_e2c2 {
  strings:
    $key_e2c2 = { b5 b0 [2] 87 92 [2] 81 a7 [2] af a7 [2] 90 bb }

  condition:
    any of them
}