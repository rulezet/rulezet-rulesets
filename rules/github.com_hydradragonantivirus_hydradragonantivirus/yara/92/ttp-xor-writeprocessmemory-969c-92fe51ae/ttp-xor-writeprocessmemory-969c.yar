rule TTP_XOR_WriteProcessMemory_969c {
  strings:
    $key_969c = { c1 ee [2] f3 cc [2] f5 f9 [2] db f9 [2] e4 e5 }

  condition:
    any of them
}