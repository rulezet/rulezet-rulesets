rule TTP_XOR_WriteProcessMemory_0bc2 {
  strings:
    $key_0bc2 = { 5c b0 [2] 6e 92 [2] 68 a7 [2] 46 a7 [2] 79 bb }

  condition:
    any of them
}