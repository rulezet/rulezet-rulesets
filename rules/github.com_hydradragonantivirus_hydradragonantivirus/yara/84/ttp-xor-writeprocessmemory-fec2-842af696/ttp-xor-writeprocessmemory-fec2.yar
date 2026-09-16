rule TTP_XOR_WriteProcessMemory_fec2 {
  strings:
    $key_fec2 = { a9 b0 [2] 9b 92 [2] 9d a7 [2] b3 a7 [2] 8c bb }

  condition:
    any of them
}