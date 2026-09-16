rule TTP_XOR_WriteProcessMemory_fac2 {
  strings:
    $key_fac2 = { ad b0 [2] 9f 92 [2] 99 a7 [2] b7 a7 [2] 88 bb }

  condition:
    any of them
}