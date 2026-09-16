rule TTP_XOR_WriteProcessMemory_cf94 {
  strings:
    $key_cf94 = { 98 e6 [2] aa c4 [2] ac f1 [2] 82 f1 [2] bd ed }

  condition:
    any of them
}