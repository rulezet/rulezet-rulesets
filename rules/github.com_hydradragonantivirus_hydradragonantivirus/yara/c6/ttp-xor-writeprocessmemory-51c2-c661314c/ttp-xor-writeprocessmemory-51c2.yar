rule TTP_XOR_WriteProcessMemory_51c2 {
  strings:
    $key_51c2 = { 06 b0 [2] 34 92 [2] 32 a7 [2] 1c a7 [2] 23 bb }

  condition:
    any of them
}