rule TTP_XOR_WriteProcessMemory_62c2 {
  strings:
    $key_62c2 = { 35 b0 [2] 07 92 [2] 01 a7 [2] 2f a7 [2] 10 bb }

  condition:
    any of them
}