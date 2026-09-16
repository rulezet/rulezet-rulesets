rule TTP_XOR_WriteProcessMemory_cf08 {
  strings:
    $key_cf08 = { 98 7a [2] aa 58 [2] ac 6d [2] 82 6d [2] bd 71 }

  condition:
    any of them
}