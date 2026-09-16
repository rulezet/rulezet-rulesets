rule TTP_XOR_WriteProcessMemory_cf63 {
  strings:
    $key_cf63 = { 98 11 [2] aa 33 [2] ac 06 [2] 82 06 [2] bd 1a }

  condition:
    any of them
}