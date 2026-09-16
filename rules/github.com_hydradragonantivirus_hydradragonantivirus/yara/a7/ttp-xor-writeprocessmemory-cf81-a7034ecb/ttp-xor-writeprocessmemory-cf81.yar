rule TTP_XOR_WriteProcessMemory_cf81 {
  strings:
    $key_cf81 = { 98 f3 [2] aa d1 [2] ac e4 [2] 82 e4 [2] bd f8 }

  condition:
    any of them
}