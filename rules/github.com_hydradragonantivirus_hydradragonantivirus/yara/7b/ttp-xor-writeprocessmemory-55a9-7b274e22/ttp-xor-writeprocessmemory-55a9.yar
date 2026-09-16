rule TTP_XOR_WriteProcessMemory_55a9 {
  strings:
    $key_55a9 = { 02 db [2] 30 f9 [2] 36 cc [2] 18 cc [2] 27 d0 }

  condition:
    any of them
}