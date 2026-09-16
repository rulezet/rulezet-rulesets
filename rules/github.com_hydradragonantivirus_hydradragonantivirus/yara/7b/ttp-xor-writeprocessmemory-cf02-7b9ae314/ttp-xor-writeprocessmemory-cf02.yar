rule TTP_XOR_WriteProcessMemory_cf02 {
  strings:
    $key_cf02 = { 98 70 [2] aa 52 [2] ac 67 [2] 82 67 [2] bd 7b }

  condition:
    any of them
}