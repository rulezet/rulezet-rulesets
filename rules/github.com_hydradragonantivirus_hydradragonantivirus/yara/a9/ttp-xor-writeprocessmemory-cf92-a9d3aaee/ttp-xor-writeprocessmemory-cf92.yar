rule TTP_XOR_WriteProcessMemory_cf92 {
  strings:
    $key_cf92 = { 98 e0 [2] aa c2 [2] ac f7 [2] 82 f7 [2] bd eb }

  condition:
    any of them
}