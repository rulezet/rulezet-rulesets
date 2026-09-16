rule TTP_XOR_WriteProcessMemory_cac2 {
  strings:
    $key_cac2 = { 9d b0 [2] af 92 [2] a9 a7 [2] 87 a7 [2] b8 bb }

  condition:
    any of them
}