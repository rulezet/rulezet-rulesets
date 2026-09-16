rule TTP_XOR_WriteProcessMemory_26c2 {
  strings:
    $key_26c2 = { 71 b0 [2] 43 92 [2] 45 a7 [2] 6b a7 [2] 54 bb }

  condition:
    any of them
}