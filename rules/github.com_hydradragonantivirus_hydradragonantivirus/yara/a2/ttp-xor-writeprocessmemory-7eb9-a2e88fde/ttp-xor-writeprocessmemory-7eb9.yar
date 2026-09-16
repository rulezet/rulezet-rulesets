rule TTP_XOR_WriteProcessMemory_7eb9 {
  strings:
    $key_7eb9 = { 29 cb [2] 1b e9 [2] 1d dc [2] 33 dc [2] 0c c0 }

  condition:
    any of them
}