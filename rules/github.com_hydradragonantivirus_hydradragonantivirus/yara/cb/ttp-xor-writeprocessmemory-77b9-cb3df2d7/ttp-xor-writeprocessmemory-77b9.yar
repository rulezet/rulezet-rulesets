rule TTP_XOR_WriteProcessMemory_77b9 {
  strings:
    $key_77b9 = { 20 cb [2] 12 e9 [2] 14 dc [2] 3a dc [2] 05 c0 }

  condition:
    any of them
}