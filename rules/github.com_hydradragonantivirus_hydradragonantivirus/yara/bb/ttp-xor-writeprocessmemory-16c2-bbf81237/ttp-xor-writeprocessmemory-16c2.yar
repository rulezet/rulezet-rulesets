rule TTP_XOR_WriteProcessMemory_16c2 {
  strings:
    $key_16c2 = { 41 b0 [2] 73 92 [2] 75 a7 [2] 5b a7 [2] 64 bb }

  condition:
    any of them
}