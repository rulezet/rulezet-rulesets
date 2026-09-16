rule TTP_XOR_WriteProcessMemory_973e {
  strings:
    $key_973e = { c0 4c [2] f2 6e [2] f4 5b [2] da 5b [2] e5 47 }

  condition:
    any of them
}