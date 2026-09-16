rule TTP_XOR_WriteProcessMemory_f19c {
  strings:
    $key_f19c = { a6 ee [2] 94 cc [2] 92 f9 [2] bc f9 [2] 83 e5 }

  condition:
    any of them
}