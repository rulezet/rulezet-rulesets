rule TTP_XOR_WriteProcessMemory_44c2 {
  strings:
    $key_44c2 = { 13 b0 [2] 21 92 [2] 27 a7 [2] 09 a7 [2] 36 bb }

  condition:
    any of them
}