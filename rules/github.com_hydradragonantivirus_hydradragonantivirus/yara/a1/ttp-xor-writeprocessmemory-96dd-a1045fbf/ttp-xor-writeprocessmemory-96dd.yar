rule TTP_XOR_WriteProcessMemory_96dd {
  strings:
    $key_96dd = { c1 af [2] f3 8d [2] f5 b8 [2] db b8 [2] e4 a4 }

  condition:
    any of them
}