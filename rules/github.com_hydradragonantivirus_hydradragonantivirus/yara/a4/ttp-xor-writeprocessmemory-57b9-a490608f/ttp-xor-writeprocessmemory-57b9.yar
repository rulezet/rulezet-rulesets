rule TTP_XOR_WriteProcessMemory_57b9 {
  strings:
    $key_57b9 = { 00 cb [2] 32 e9 [2] 34 dc [2] 1a dc [2] 25 c0 }

  condition:
    any of them
}