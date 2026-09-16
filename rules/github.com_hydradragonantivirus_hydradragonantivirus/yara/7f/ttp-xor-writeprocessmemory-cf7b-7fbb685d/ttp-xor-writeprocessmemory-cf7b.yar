rule TTP_XOR_WriteProcessMemory_cf7b {
  strings:
    $key_cf7b = { 98 09 [2] aa 2b [2] ac 1e [2] 82 1e [2] bd 02 }

  condition:
    any of them
}