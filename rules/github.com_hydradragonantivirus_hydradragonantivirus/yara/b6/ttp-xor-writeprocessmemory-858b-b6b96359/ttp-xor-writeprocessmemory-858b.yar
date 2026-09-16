rule TTP_XOR_WriteProcessMemory_858b {
  strings:
    $key_858b = { d2 f9 [2] e0 db [2] e6 ee [2] c8 ee [2] f7 f2 }

  condition:
    any of them
}