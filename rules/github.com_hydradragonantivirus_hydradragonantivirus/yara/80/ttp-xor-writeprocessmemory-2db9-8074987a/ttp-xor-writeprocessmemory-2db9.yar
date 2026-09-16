rule TTP_XOR_WriteProcessMemory_2db9 {
  strings:
    $key_2db9 = { 7a cb [2] 48 e9 [2] 4e dc [2] 60 dc [2] 5f c0 }

  condition:
    any of them
}