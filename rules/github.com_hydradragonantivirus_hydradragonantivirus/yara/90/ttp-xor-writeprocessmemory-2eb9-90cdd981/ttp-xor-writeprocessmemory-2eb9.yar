rule TTP_XOR_WriteProcessMemory_2eb9 {
  strings:
    $key_2eb9 = { 79 cb [2] 4b e9 [2] 4d dc [2] 63 dc [2] 5c c0 }

  condition:
    any of them
}