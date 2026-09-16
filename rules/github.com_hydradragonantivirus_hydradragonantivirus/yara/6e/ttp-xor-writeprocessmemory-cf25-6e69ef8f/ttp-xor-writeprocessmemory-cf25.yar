rule TTP_XOR_WriteProcessMemory_cf25 {
  strings:
    $key_cf25 = { 98 57 [2] aa 75 [2] ac 40 [2] 82 40 [2] bd 5c }

  condition:
    any of them
}