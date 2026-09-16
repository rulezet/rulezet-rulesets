rule TTP_XOR_WriteProcessMemory_cf5d {
  strings:
    $key_cf5d = { 98 2f [2] aa 0d [2] ac 38 [2] 82 38 [2] bd 24 }

  condition:
    any of them
}