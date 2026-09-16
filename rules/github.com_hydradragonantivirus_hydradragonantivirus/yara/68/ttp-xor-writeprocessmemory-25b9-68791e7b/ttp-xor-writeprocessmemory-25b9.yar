rule TTP_XOR_WriteProcessMemory_25b9 {
  strings:
    $key_25b9 = { 72 cb [2] 40 e9 [2] 46 dc [2] 68 dc [2] 57 c0 }

  condition:
    any of them
}