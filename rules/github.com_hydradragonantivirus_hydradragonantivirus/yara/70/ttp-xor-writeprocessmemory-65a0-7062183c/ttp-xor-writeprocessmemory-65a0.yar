rule TTP_XOR_WriteProcessMemory_65a0 {
  strings:
    $key_65a0 = { 32 d2 [2] 00 f0 [2] 06 c5 [2] 28 c5 [2] 17 d9 }

  condition:
    any of them
}