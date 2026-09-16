rule TTP_XOR_WriteProcessMemory_52a9 {
  strings:
    $key_52a9 = { 05 db [2] 37 f9 [2] 31 cc [2] 1f cc [2] 20 d0 }

  condition:
    any of them
}