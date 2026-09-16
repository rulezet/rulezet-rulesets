rule TTP_XOR_WriteProcessMemory_3eb9 {
  strings:
    $key_3eb9 = { 69 cb [2] 5b e9 [2] 5d dc [2] 73 dc [2] 4c c0 }

  condition:
    any of them
}