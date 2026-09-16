rule TTP_XOR_WriteProcessMemory_e7c2 {
  strings:
    $key_e7c2 = { b0 b0 [2] 82 92 [2] 84 a7 [2] aa a7 [2] 95 bb }

  condition:
    any of them
}