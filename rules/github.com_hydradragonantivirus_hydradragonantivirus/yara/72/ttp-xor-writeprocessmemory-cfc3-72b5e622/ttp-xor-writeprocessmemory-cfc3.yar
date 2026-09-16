rule TTP_XOR_WriteProcessMemory_cfc3 {
  strings:
    $key_cfc3 = { 98 b1 [2] aa 93 [2] ac a6 [2] 82 a6 [2] bd ba }

  condition:
    any of them
}