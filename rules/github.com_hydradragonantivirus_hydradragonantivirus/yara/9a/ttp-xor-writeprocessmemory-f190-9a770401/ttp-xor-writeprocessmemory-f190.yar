rule TTP_XOR_WriteProcessMemory_f190 {
  strings:
    $key_f190 = { a6 e2 [2] 94 c0 [2] 92 f5 [2] bc f5 [2] 83 e9 }

  condition:
    any of them
}