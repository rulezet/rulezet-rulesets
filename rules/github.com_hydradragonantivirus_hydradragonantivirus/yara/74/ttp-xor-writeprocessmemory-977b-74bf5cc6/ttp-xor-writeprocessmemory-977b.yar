rule TTP_XOR_WriteProcessMemory_977b {
  strings:
    $key_977b = { c0 09 [2] f2 2b [2] f4 1e [2] da 1e [2] e5 02 }

  condition:
    any of them
}