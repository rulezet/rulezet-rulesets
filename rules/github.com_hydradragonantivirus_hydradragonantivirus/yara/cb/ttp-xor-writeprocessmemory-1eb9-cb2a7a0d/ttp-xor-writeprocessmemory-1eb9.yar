rule TTP_XOR_WriteProcessMemory_1eb9 {
  strings:
    $key_1eb9 = { 49 cb [2] 7b e9 [2] 7d dc [2] 53 dc [2] 6c c0 }

  condition:
    any of them
}