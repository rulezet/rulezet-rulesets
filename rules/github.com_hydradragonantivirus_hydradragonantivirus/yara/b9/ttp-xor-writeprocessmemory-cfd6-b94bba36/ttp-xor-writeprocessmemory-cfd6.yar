rule TTP_XOR_WriteProcessMemory_cfd6 {
  strings:
    $key_cfd6 = { 98 a4 [2] aa 86 [2] ac b3 [2] 82 b3 [2] bd af }

  condition:
    any of them
}