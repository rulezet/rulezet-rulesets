rule TTP_XOR_WriteProcessMemory_96a9 {
  strings:
    $key_96a9 = { c1 db [2] f3 f9 [2] f5 cc [2] db cc [2] e4 d0 }

  condition:
    any of them
}