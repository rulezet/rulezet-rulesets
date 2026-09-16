rule TTP_XOR_WriteProcessMemory_fbc2 {
  strings:
    $key_fbc2 = { ac b0 [2] 9e 92 [2] 98 a7 [2] b6 a7 [2] 89 bb }

  condition:
    any of them
}