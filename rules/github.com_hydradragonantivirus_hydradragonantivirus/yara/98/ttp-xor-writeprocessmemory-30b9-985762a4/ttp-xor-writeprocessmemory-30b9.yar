rule TTP_XOR_WriteProcessMemory_30b9 {
  strings:
    $key_30b9 = { 67 cb [2] 55 e9 [2] 53 dc [2] 7d dc [2] 42 c0 }

  condition:
    any of them
}