rule TTP_XOR_WriteProcessMemory_75b9 {
  strings:
    $key_75b9 = { 22 cb [2] 10 e9 [2] 16 dc [2] 38 dc [2] 07 c0 }

  condition:
    any of them
}