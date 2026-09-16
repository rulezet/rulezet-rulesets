rule TTP_XOR_WriteProcessMemory_65a6 {
  strings:
    $key_65a6 = { 32 d4 [2] 00 f6 [2] 06 c3 [2] 28 c3 [2] 17 df }

  condition:
    any of them
}