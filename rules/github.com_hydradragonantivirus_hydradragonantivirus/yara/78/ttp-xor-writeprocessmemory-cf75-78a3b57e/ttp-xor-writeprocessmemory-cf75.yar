rule TTP_XOR_WriteProcessMemory_cf75 {
  strings:
    $key_cf75 = { 98 07 [2] aa 25 [2] ac 10 [2] 82 10 [2] bd 0c }

  condition:
    any of them
}