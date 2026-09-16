rule TTP_XOR_WriteProcessMemory_65e0 {
  strings:
    $key_65e0 = { 32 92 [2] 00 b0 [2] 06 85 [2] 28 85 [2] 17 99 }

  condition:
    any of them
}