rule TTP_XOR_WriteProcessMemory_cf4c {
  strings:
    $key_cf4c = { 98 3e [2] aa 1c [2] ac 29 [2] 82 29 [2] bd 35 }

  condition:
    any of them
}