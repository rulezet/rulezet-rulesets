rule TTP_XOR_WriteProcessMemory_cf0b {
  strings:
    $key_cf0b = { 98 79 [2] aa 5b [2] ac 6e [2] 82 6e [2] bd 72 }

  condition:
    any of them
}