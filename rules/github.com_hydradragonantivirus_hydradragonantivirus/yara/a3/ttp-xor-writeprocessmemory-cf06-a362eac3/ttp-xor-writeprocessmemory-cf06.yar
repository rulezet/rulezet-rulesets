rule TTP_XOR_WriteProcessMemory_cf06 {
  strings:
    $key_cf06 = { 98 74 [2] aa 56 [2] ac 63 [2] 82 63 [2] bd 7f }

  condition:
    any of them
}