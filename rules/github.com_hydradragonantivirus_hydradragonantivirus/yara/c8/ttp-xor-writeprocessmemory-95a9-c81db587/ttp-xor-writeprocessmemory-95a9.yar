rule TTP_XOR_WriteProcessMemory_95a9 {
  strings:
    $key_95a9 = { c2 db [2] f0 f9 [2] f6 cc [2] d8 cc [2] e7 d0 }

  condition:
    any of them
}