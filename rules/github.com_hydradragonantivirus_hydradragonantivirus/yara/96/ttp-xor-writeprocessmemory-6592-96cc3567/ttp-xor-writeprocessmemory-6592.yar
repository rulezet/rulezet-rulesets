rule TTP_XOR_WriteProcessMemory_6592 {
  strings:
    $key_6592 = { 32 e0 [2] 00 c2 [2] 06 f7 [2] 28 f7 [2] 17 eb }

  condition:
    any of them
}