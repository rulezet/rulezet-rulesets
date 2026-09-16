rule TTP_XOR_WriteProcessMemory_cfd7 {
  strings:
    $key_cfd7 = { 98 a5 [2] aa 87 [2] ac b2 [2] 82 b2 [2] bd ae }

  condition:
    any of them
}