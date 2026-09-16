rule TTP_XOR_WriteProcessMemory_81a9 {
  strings:
    $key_81a9 = { d6 db [2] e4 f9 [2] e2 cc [2] cc cc [2] f3 d0 }

  condition:
    any of them
}