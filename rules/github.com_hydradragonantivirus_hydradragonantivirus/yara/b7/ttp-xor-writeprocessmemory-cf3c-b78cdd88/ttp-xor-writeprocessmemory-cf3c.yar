rule TTP_XOR_WriteProcessMemory_cf3c {
  strings:
    $key_cf3c = { 98 4e [2] aa 6c [2] ac 59 [2] 82 59 [2] bd 45 }

  condition:
    any of them
}