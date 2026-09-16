rule TTP_XOR_WriteProcessMemory_cf15 {
  strings:
    $key_cf15 = { 98 67 [2] aa 45 [2] ac 70 [2] 82 70 [2] bd 6c }

  condition:
    any of them
}