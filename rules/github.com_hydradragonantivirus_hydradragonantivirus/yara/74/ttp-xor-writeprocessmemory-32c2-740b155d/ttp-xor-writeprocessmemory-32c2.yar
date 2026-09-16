rule TTP_XOR_WriteProcessMemory_32c2 {
  strings:
    $key_32c2 = { 65 b0 [2] 57 92 [2] 51 a7 [2] 7f a7 [2] 40 bb }

  condition:
    any of them
}