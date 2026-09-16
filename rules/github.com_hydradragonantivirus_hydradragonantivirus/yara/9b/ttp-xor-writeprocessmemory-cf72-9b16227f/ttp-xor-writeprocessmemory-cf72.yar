rule TTP_XOR_WriteProcessMemory_cf72 {
  strings:
    $key_cf72 = { 98 00 [2] aa 22 [2] ac 17 [2] 82 17 [2] bd 0b }

  condition:
    any of them
}