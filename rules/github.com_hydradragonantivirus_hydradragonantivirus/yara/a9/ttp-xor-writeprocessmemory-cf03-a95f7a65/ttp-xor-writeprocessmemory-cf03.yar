rule TTP_XOR_WriteProcessMemory_cf03 {
  strings:
    $key_cf03 = { 98 71 [2] aa 53 [2] ac 66 [2] 82 66 [2] bd 7a }

  condition:
    any of them
}