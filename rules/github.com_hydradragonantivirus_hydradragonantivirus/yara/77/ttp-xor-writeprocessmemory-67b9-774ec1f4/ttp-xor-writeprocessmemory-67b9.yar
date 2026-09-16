rule TTP_XOR_WriteProcessMemory_67b9 {
  strings:
    $key_67b9 = { 30 cb [2] 02 e9 [2] 04 dc [2] 2a dc [2] 15 c0 }

  condition:
    any of them
}