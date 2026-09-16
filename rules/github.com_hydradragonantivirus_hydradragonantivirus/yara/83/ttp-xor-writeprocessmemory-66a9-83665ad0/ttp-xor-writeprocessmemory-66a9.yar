rule TTP_XOR_WriteProcessMemory_66a9 {
  strings:
    $key_66a9 = { 31 db [2] 03 f9 [2] 05 cc [2] 2b cc [2] 14 d0 }

  condition:
    any of them
}