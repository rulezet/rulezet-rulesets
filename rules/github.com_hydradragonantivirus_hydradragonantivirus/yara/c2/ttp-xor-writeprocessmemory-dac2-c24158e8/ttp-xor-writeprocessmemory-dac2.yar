rule TTP_XOR_WriteProcessMemory_dac2 {
  strings:
    $key_dac2 = { 8d b0 [2] bf 92 [2] b9 a7 [2] 97 a7 [2] a8 bb }

  condition:
    any of them
}