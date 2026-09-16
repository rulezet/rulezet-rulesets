rule TTP_XOR_WriteProcessMemory_53b9 {
  strings:
    $key_53b9 = { 04 cb [2] 36 e9 [2] 30 dc [2] 1e dc [2] 21 c0 }

  condition:
    any of them
}