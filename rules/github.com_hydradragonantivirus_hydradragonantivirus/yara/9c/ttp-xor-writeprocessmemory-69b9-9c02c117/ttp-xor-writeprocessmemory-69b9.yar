rule TTP_XOR_WriteProcessMemory_69b9 {
  strings:
    $key_69b9 = { 3e cb [2] 0c e9 [2] 0a dc [2] 24 dc [2] 1b c0 }

  condition:
    any of them
}