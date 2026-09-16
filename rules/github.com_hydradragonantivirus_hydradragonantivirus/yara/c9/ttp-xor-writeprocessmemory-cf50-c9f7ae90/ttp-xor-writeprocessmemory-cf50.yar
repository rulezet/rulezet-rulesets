rule TTP_XOR_WriteProcessMemory_cf50 {
  strings:
    $key_cf50 = { 98 22 [2] aa 00 [2] ac 35 [2] 82 35 [2] bd 29 }

  condition:
    any of them
}