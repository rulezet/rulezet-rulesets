rule TTP_XOR_WriteProcessMemory_07b9 {
  strings:
    $key_07b9 = { 50 cb [2] 62 e9 [2] 64 dc [2] 4a dc [2] 75 c0 }

  condition:
    any of them
}