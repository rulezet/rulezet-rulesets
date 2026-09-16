rule TTP_XOR_WriteProcessMemory_cf8b {
  strings:
    $key_cf8b = { 98 f9 [2] aa db [2] ac ee [2] 82 ee [2] bd f2 }

  condition:
    any of them
}