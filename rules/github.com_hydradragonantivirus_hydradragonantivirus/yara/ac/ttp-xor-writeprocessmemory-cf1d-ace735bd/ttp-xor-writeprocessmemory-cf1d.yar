rule TTP_XOR_WriteProcessMemory_cf1d {
  strings:
    $key_cf1d = { 98 6f [2] aa 4d [2] ac 78 [2] 82 78 [2] bd 64 }

  condition:
    any of them
}