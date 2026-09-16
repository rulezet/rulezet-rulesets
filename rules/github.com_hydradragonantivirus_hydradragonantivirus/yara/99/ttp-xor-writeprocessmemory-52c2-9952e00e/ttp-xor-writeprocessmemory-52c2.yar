rule TTP_XOR_WriteProcessMemory_52c2 {
  strings:
    $key_52c2 = { 05 b0 [2] 37 92 [2] 31 a7 [2] 1f a7 [2] 20 bb }

  condition:
    any of them
}