rule TTP_XOR_WriteProcessMemory_cf00 {
  strings:
    $key_cf00 = { 98 72 [2] aa 50 [2] ac 65 [2] 82 65 [2] bd 79 }

  condition:
    any of them
}