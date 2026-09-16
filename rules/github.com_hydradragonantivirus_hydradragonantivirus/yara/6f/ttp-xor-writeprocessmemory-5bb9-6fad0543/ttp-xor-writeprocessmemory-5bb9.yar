rule TTP_XOR_WriteProcessMemory_5bb9 {
  strings:
    $key_5bb9 = { 0c cb [2] 3e e9 [2] 38 dc [2] 16 dc [2] 29 c0 }

  condition:
    any of them
}