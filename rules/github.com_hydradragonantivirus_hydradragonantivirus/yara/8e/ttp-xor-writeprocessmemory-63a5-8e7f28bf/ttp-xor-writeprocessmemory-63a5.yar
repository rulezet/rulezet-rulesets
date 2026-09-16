rule TTP_XOR_WriteProcessMemory_63a5 {
  strings:
    $key_63a5 = { 34 d7 [2] 06 f5 [2] 00 c0 [2] 2e c0 [2] 11 dc }

  condition:
    any of them
}