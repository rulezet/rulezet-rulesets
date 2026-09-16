rule TTP_XOR_WriteProcessMemory_7bc2 {
  strings:
    $key_7bc2 = { 2c b0 [2] 1e 92 [2] 18 a7 [2] 36 a7 [2] 09 bb }

  condition:
    any of them
}