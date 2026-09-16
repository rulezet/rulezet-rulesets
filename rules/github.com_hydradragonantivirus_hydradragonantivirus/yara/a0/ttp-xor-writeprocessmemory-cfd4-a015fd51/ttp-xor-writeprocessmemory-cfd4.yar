rule TTP_XOR_WriteProcessMemory_cfd4 {
  strings:
    $key_cfd4 = { 98 a6 [2] aa 84 [2] ac b1 [2] 82 b1 [2] bd ad }

  condition:
    any of them
}