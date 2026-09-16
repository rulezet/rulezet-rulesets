rule TTP_XOR_WriteProcessMemory_cf5b {
  strings:
    $key_cf5b = { 98 29 [2] aa 0b [2] ac 3e [2] 82 3e [2] bd 22 }

  condition:
    any of them
}