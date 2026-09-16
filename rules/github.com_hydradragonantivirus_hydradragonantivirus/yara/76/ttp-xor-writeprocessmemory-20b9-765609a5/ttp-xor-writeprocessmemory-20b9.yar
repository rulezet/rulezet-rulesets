rule TTP_XOR_WriteProcessMemory_20b9 {
  strings:
    $key_20b9 = { 77 cb [2] 45 e9 [2] 43 dc [2] 6d dc [2] 52 c0 }

  condition:
    any of them
}