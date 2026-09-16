rule TTP_XOR_WriteProcessMemory_65b9 {
  strings:
    $key_65b9 = { 32 cb [2] 00 e9 [2] 06 dc [2] 28 dc [2] 17 c0 }

  condition:
    any of them
}