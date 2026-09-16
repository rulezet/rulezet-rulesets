rule TTP_XOR_WriteProcessMemory_cf1e {
  strings:
    $key_cf1e = { 98 6c [2] aa 4e [2] ac 7b [2] 82 7b [2] bd 67 }

  condition:
    any of them
}