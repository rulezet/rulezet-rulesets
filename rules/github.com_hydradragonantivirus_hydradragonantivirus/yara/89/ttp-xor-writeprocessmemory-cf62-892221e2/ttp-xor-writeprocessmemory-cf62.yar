rule TTP_XOR_WriteProcessMemory_cf62 {
  strings:
    $key_cf62 = { 98 10 [2] aa 32 [2] ac 07 [2] 82 07 [2] bd 1b }

  condition:
    any of them
}