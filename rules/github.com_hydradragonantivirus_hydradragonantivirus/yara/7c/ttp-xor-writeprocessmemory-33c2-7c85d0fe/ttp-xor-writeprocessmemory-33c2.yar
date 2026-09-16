rule TTP_XOR_WriteProcessMemory_33c2 {
  strings:
    $key_33c2 = { 64 b0 [2] 56 92 [2] 50 a7 [2] 7e a7 [2] 41 bb }

  condition:
    any of them
}