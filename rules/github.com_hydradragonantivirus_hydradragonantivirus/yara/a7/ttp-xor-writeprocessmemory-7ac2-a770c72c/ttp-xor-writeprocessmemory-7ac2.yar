rule TTP_XOR_WriteProcessMemory_7ac2 {
  strings:
    $key_7ac2 = { 2d b0 [2] 1f 92 [2] 19 a7 [2] 37 a7 [2] 08 bb }

  condition:
    any of them
}