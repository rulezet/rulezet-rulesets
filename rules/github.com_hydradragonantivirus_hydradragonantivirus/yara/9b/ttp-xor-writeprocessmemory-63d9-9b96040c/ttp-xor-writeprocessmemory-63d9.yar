rule TTP_XOR_WriteProcessMemory_63d9 {
  strings:
    $key_63d9 = { 34 ab [2] 06 89 [2] 00 bc [2] 2e bc [2] 11 a0 }

  condition:
    any of them
}