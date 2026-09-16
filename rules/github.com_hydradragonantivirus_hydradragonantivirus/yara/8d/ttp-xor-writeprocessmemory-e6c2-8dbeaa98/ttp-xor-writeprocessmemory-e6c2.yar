rule TTP_XOR_WriteProcessMemory_e6c2 {
  strings:
    $key_e6c2 = { b1 b0 [2] 83 92 [2] 85 a7 [2] ab a7 [2] 94 bb }

  condition:
    any of them
}