rule TTP_XOR_WriteProcessMemory_cf70 {
  strings:
    $key_cf70 = { 98 02 [2] aa 20 [2] ac 15 [2] 82 15 [2] bd 09 }

  condition:
    any of them
}