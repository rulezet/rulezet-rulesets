rule TTP_XOR_WriteProcessMemory_63a2 {
  strings:
    $key_63a2 = { 34 d0 [2] 06 f2 [2] 00 c7 [2] 2e c7 [2] 11 db }

  condition:
    any of them
}