rule TTP_XOR_WriteProcessMemory_1ac2 {
  strings:
    $key_1ac2 = { 4d b0 [2] 7f 92 [2] 79 a7 [2] 57 a7 [2] 68 bb }

  condition:
    any of them
}