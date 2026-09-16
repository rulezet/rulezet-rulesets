rule TTP_XOR_WriteProcessMemory_cf2b {
  strings:
    $key_cf2b = { 98 59 [2] aa 7b [2] ac 4e [2] 82 4e [2] bd 52 }

  condition:
    any of them
}