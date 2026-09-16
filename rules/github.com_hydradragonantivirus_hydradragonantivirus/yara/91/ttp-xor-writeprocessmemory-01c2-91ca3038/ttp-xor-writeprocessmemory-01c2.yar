rule TTP_XOR_WriteProcessMemory_01c2 {
  strings:
    $key_01c2 = { 56 b0 [2] 64 92 [2] 62 a7 [2] 4c a7 [2] 73 bb }

  condition:
    any of them
}