rule TTP_XOR_WriteProcessMemory_83be {
  strings:
    $key_83be = { d4 cc [2] e6 ee [2] e0 db [2] ce db [2] f1 c7 }

  condition:
    any of them
}