rule TTP_XOR_WriteProcessMemory_cfc0 {
  strings:
    $key_cfc0 = { 98 b2 [2] aa 90 [2] ac a5 [2] 82 a5 [2] bd b9 }

  condition:
    any of them
}