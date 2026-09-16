rule TTP_XOR_WriteProcessMemory_1bc2 {
  strings:
    $key_1bc2 = { 4c b0 [2] 7e 92 [2] 78 a7 [2] 56 a7 [2] 69 bb }

  condition:
    any of them
}