rule TTP_XOR_WriteProcessMemory_cf8a {
  strings:
    $key_cf8a = { 98 f8 [2] aa da [2] ac ef [2] 82 ef [2] bd f3 }

  condition:
    any of them
}