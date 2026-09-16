rule TTP_XOR_WriteProcessMemory_78b9 {
  strings:
    $key_78b9 = { 2f cb [2] 1d e9 [2] 1b dc [2] 35 dc [2] 0a c0 }

  condition:
    any of them
}