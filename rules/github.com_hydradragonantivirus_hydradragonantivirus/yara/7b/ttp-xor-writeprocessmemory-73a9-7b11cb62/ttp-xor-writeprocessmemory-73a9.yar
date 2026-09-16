rule TTP_XOR_WriteProcessMemory_73a9 {
  strings:
    $key_73a9 = { 24 db [2] 16 f9 [2] 10 cc [2] 3e cc [2] 01 d0 }

  condition:
    any of them
}