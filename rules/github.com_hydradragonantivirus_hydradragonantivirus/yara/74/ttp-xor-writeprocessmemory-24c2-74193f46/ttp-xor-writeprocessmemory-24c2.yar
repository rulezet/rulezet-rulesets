rule TTP_XOR_WriteProcessMemory_24c2 {
  strings:
    $key_24c2 = { 73 b0 [2] 41 92 [2] 47 a7 [2] 69 a7 [2] 56 bb }

  condition:
    any of them
}