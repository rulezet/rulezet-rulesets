rule TTP_XOR_WriteProcessMemory_50b9 {
  strings:
    $key_50b9 = { 07 cb [2] 35 e9 [2] 33 dc [2] 1d dc [2] 22 c0 }

  condition:
    any of them
}