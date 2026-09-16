rule TTP_XOR_WriteProcessMemory_cf74 {
  strings:
    $key_cf74 = { 98 06 [2] aa 24 [2] ac 11 [2] 82 11 [2] bd 0d }

  condition:
    any of them
}