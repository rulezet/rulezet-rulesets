rule TTP_XOR_WriteProcessMemory_cf6e {
  strings:
    $key_cf6e = { 98 1c [2] aa 3e [2] ac 0b [2] 82 0b [2] bd 17 }

  condition:
    any of them
}