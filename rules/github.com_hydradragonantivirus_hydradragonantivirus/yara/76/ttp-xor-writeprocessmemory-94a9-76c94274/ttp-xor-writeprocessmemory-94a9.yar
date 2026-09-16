rule TTP_XOR_WriteProcessMemory_94a9 {
  strings:
    $key_94a9 = { c3 db [2] f1 f9 [2] f7 cc [2] d9 cc [2] e6 d0 }

  condition:
    any of them
}