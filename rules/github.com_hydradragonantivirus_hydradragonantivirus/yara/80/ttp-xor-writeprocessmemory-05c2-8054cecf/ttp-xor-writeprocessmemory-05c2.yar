rule TTP_XOR_WriteProcessMemory_05c2 {
  strings:
    $key_05c2 = { 52 b0 [2] 60 92 [2] 66 a7 [2] 48 a7 [2] 77 bb }

  condition:
    any of them
}