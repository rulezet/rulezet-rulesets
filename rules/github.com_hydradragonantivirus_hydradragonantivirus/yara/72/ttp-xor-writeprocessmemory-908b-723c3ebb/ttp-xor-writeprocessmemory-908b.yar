rule TTP_XOR_WriteProcessMemory_908b {
  strings:
    $key_908b = { c7 f9 [2] f5 db [2] f3 ee [2] dd ee [2] e2 f2 }

  condition:
    any of them
}