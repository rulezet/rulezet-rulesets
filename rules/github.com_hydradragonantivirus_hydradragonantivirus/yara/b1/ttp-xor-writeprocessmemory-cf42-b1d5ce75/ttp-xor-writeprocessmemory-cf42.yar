rule TTP_XOR_WriteProcessMemory_cf42 {
  strings:
    $key_cf42 = { 98 30 [2] aa 12 [2] ac 27 [2] 82 27 [2] bd 3b }

  condition:
    any of them
}