rule TTP_XOR_WriteProcessMemory_f192 {
  strings:
    $key_f192 = { a6 e0 [2] 94 c2 [2] 92 f7 [2] bc f7 [2] 83 eb }

  condition:
    any of them
}