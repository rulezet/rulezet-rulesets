rule TTP_XOR_WriteProcessMemory_3ac2 {
  strings:
    $key_3ac2 = { 6d b0 [2] 5f 92 [2] 59 a7 [2] 77 a7 [2] 48 bb }

  condition:
    any of them
}