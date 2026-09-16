rule TTP_XOR_WriteProcessMemory_cf68 {
  strings:
    $key_cf68 = { 98 1a [2] aa 38 [2] ac 0d [2] 82 0d [2] bd 11 }

  condition:
    any of them
}