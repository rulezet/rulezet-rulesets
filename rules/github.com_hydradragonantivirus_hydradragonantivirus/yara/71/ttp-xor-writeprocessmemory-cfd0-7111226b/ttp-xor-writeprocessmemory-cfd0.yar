rule TTP_XOR_WriteProcessMemory_cfd0 {
  strings:
    $key_cfd0 = { 98 a2 [2] aa 80 [2] ac b5 [2] 82 b5 [2] bd a9 }

  condition:
    any of them
}