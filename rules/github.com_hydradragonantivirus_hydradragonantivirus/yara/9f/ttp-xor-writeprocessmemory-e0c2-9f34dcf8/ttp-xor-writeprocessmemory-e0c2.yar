rule TTP_XOR_WriteProcessMemory_e0c2 {
  strings:
    $key_e0c2 = { b7 b0 [2] 85 92 [2] 83 a7 [2] ad a7 [2] 92 bb }

  condition:
    any of them
}