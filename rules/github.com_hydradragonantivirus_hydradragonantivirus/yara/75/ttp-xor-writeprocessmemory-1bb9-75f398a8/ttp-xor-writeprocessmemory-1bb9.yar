rule TTP_XOR_WriteProcessMemory_1bb9 {
  strings:
    $key_1bb9 = { 4c cb [2] 7e e9 [2] 78 dc [2] 56 dc [2] 69 c0 }

  condition:
    any of them
}