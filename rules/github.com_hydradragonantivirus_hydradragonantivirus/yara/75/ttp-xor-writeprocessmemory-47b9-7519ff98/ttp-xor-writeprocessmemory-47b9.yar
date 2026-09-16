rule TTP_XOR_WriteProcessMemory_47b9 {
  strings:
    $key_47b9 = { 10 cb [2] 22 e9 [2] 24 dc [2] 0a dc [2] 35 c0 }

  condition:
    any of them
}