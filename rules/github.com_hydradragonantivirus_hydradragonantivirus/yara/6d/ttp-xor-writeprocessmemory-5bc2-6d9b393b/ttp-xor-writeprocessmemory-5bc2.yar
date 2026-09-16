rule TTP_XOR_WriteProcessMemory_5bc2 {
  strings:
    $key_5bc2 = { 0c b0 [2] 3e 92 [2] 38 a7 [2] 16 a7 [2] 29 bb }

  condition:
    any of them
}