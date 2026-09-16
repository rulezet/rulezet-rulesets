rule TTP_XOR_WriteProcessMemory_63a3 {
  strings:
    $key_63a3 = { 34 d1 [2] 06 f3 [2] 00 c6 [2] 2e c6 [2] 11 da }

  condition:
    any of them
}