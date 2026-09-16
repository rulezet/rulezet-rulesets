rule TTP_XOR_WriteProcessMemory_cf43 {
  strings:
    $key_cf43 = { 98 31 [2] aa 13 [2] ac 26 [2] 82 26 [2] bd 3a }

  condition:
    any of them
}