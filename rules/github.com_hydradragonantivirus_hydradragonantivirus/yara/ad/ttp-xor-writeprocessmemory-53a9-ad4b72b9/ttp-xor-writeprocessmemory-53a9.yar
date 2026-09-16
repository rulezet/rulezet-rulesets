rule TTP_XOR_WriteProcessMemory_53a9 {
  strings:
    $key_53a9 = { 04 db [2] 36 f9 [2] 30 cc [2] 1e cc [2] 21 d0 }

  condition:
    any of them
}