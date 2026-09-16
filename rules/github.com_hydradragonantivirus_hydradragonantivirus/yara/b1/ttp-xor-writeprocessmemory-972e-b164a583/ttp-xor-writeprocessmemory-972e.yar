rule TTP_XOR_WriteProcessMemory_972e {
  strings:
    $key_972e = { c0 5c [2] f2 7e [2] f4 4b [2] da 4b [2] e5 57 }

  condition:
    any of them
}