rule TTP_XOR_WriteProcessMemory_4bc2 {
  strings:
    $key_4bc2 = { 1c b0 [2] 2e 92 [2] 28 a7 [2] 06 a7 [2] 39 bb }

  condition:
    any of them
}