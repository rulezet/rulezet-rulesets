rule TTP_XOR_WriteProcessMemory_e8b9 {
  strings:
    $key_e8b9 = { bf cb [2] 8d e9 [2] 8b dc [2] a5 dc [2] 9a c0 }

  condition:
    any of them
}