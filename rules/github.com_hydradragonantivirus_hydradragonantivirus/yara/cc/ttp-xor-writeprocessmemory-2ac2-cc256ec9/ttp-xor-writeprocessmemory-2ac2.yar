rule TTP_XOR_WriteProcessMemory_2ac2 {
  strings:
    $key_2ac2 = { 7d b0 [2] 4f 92 [2] 49 a7 [2] 67 a7 [2] 58 bb }

  condition:
    any of them
}