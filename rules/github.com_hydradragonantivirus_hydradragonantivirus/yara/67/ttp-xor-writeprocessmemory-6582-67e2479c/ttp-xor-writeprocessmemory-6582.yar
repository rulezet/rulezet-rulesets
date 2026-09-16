rule TTP_XOR_WriteProcessMemory_6582 {
  strings:
    $key_6582 = { 32 f0 [2] 00 d2 [2] 06 e7 [2] 28 e7 [2] 17 fb }

  condition:
    any of them
}