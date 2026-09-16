rule TTP_XOR_WriteProcessMemory_cf41 {
  strings:
    $key_cf41 = { 98 33 [2] aa 11 [2] ac 24 [2] 82 24 [2] bd 38 }

  condition:
    any of them
}