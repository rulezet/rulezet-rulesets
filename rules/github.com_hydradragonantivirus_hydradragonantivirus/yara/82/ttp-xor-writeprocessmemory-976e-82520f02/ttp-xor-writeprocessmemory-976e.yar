rule TTP_XOR_WriteProcessMemory_976e {
  strings:
    $key_976e = { c0 1c [2] f2 3e [2] f4 0b [2] da 0b [2] e5 17 }

  condition:
    any of them
}