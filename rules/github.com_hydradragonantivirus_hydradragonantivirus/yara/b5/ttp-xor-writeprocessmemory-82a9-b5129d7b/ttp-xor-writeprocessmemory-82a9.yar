rule TTP_XOR_WriteProcessMemory_82a9 {
  strings:
    $key_82a9 = { d5 db [2] e7 f9 [2] e1 cc [2] cf cc [2] f0 d0 }

  condition:
    any of them
}