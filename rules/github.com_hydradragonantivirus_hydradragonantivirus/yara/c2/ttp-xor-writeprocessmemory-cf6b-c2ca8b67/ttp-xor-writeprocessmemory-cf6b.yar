rule TTP_XOR_WriteProcessMemory_cf6b {
  strings:
    $key_cf6b = { 98 19 [2] aa 3b [2] ac 0e [2] 82 0e [2] bd 12 }

  condition:
    any of them
}