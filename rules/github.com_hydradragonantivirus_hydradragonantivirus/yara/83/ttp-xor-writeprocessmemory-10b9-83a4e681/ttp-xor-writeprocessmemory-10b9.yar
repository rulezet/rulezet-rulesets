rule TTP_XOR_WriteProcessMemory_10b9 {
  strings:
    $key_10b9 = { 47 cb [2] 75 e9 [2] 73 dc [2] 5d dc [2] 62 c0 }

  condition:
    any of them
}