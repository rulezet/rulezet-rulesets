rule TTP_XOR_WriteProcessMemory_60b9 {
  strings:
    $key_60b9 = { 37 cb [2] 05 e9 [2] 03 dc [2] 2d dc [2] 12 c0 }

  condition:
    any of them
}