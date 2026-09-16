rule TTP_XOR_WriteProcessMemory_a9b9 {
  strings:
    $key_a9b9 = { fe cb [2] cc e9 [2] ca dc [2] e4 dc [2] db c0 }

  condition:
    any of them
}