rule TTP_XOR_WriteProcessMemory_dcc2 {
  strings:
    $key_dcc2 = { 8b b0 [2] b9 92 [2] bf a7 [2] 91 a7 [2] ae bb }

  condition:
    any of them
}