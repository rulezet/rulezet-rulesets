rule TTP_XOR_WriteProcessMemory_cfd3 {
  strings:
    $key_cfd3 = { 98 a1 [2] aa 83 [2] ac b6 [2] 82 b6 [2] bd aa }

  condition:
    any of them
}