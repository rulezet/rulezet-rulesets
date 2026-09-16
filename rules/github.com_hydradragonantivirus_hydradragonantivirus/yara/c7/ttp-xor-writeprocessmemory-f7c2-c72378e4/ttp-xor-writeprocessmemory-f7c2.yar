rule TTP_XOR_WriteProcessMemory_f7c2 {
  strings:
    $key_f7c2 = { a0 b0 [2] 92 92 [2] 94 a7 [2] ba a7 [2] 85 bb }

  condition:
    any of them
}