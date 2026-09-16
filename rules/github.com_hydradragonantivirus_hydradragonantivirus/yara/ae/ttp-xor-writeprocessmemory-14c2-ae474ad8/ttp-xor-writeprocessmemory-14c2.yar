rule TTP_XOR_WriteProcessMemory_14c2 {
  strings:
    $key_14c2 = { 43 b0 [2] 71 92 [2] 77 a7 [2] 59 a7 [2] 66 bb }

  condition:
    any of them
}