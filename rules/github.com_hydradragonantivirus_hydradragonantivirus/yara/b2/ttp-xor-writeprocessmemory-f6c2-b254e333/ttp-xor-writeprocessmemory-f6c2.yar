rule TTP_XOR_WriteProcessMemory_f6c2 {
  strings:
    $key_f6c2 = { a1 b0 [2] 93 92 [2] 95 a7 [2] bb a7 [2] 84 bb }

  condition:
    any of them
}