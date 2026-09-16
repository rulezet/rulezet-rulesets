rule TTP_XOR_WriteProcessMemory_e0a9 {
  strings:
    $key_e0a9 = { b7 db [2] 85 f9 [2] 83 cc [2] ad cc [2] 92 d0 }

  condition:
    any of them
}