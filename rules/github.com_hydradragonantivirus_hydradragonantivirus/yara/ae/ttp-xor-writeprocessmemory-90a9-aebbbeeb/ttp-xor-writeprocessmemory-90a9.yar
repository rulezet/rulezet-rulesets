rule TTP_XOR_WriteProcessMemory_90a9 {
  strings:
    $key_90a9 = { c7 db [2] f5 f9 [2] f3 cc [2] dd cc [2] e2 d0 }

  condition:
    any of them
}