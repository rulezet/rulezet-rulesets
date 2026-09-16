rule TTP_XOR_WriteProcessMemory_06c2 {
  strings:
    $key_06c2 = { 51 b0 [2] 63 92 [2] 65 a7 [2] 4b a7 [2] 74 bb }

  condition:
    any of them
}