rule TTP_XOR_WriteProcessMemory_63f0 {
  strings:
    $key_63f0 = { 34 82 [2] 06 a0 [2] 00 95 [2] 2e 95 [2] 11 89 }

  condition:
    any of them
}