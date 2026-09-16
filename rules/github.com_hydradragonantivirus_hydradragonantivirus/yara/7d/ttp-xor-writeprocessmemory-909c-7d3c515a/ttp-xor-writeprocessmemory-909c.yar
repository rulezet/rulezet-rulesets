rule TTP_XOR_WriteProcessMemory_909c {
  strings:
    $key_909c = { c7 ee [2] f5 cc [2] f3 f9 [2] dd f9 [2] e2 e5 }

  condition:
    any of them
}