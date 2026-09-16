rule TTP_XOR_WriteProcessMemory_20a9 {
  strings:
    $key_20a9 = { 77 db [2] 45 f9 [2] 43 cc [2] 6d cc [2] 52 d0 }

  condition:
    any of them
}