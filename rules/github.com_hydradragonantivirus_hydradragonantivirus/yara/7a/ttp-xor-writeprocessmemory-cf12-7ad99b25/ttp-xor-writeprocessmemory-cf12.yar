rule TTP_XOR_WriteProcessMemory_cf12 {
  strings:
    $key_cf12 = { 98 60 [2] aa 42 [2] ac 77 [2] 82 77 [2] bd 6b }

  condition:
    any of them
}