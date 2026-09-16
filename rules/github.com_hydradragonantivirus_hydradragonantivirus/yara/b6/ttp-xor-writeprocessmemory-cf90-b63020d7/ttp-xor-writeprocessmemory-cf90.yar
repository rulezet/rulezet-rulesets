rule TTP_XOR_WriteProcessMemory_cf90 {
  strings:
    $key_cf90 = { 98 e2 [2] aa c0 [2] ac f5 [2] 82 f5 [2] bd e9 }

  condition:
    any of them
}