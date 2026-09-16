rule TTP_XOR_WriteProcessMemory_27b9 {
  strings:
    $key_27b9 = { 70 cb [2] 42 e9 [2] 44 dc [2] 6a dc [2] 55 c0 }

  condition:
    any of them
}