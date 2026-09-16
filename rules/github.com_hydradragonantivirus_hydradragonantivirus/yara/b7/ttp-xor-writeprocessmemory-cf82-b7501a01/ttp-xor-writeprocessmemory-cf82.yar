rule TTP_XOR_WriteProcessMemory_cf82 {
  strings:
    $key_cf82 = { 98 f0 [2] aa d2 [2] ac e7 [2] 82 e7 [2] bd fb }

  condition:
    any of them
}