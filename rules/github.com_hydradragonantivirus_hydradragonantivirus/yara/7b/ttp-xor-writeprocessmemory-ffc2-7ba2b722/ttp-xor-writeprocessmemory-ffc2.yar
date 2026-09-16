rule TTP_XOR_WriteProcessMemory_ffc2 {
  strings:
    $key_ffc2 = { a8 b0 [2] 9a 92 [2] 9c a7 [2] b2 a7 [2] 8d bb }

  condition:
    any of them
}