rule TTP_XOR_WriteProcessMemory_976b {
  strings:
    $key_976b = { c0 19 [2] f2 3b [2] f4 0e [2] da 0e [2] e5 12 }

  condition:
    any of them
}