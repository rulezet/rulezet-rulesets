rule TTP_XOR_WriteProcessMemory_63a9 {
  strings:
    $key_63a9 = { 34 db [2] 06 f9 [2] 00 cc [2] 2e cc [2] 11 d0 }

  condition:
    any of them
}