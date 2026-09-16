rule TTP_XOR_WriteProcessMemory_cf4e {
  strings:
    $key_cf4e = { 98 3c [2] aa 1e [2] ac 2b [2] 82 2b [2] bd 37 }

  condition:
    any of them
}