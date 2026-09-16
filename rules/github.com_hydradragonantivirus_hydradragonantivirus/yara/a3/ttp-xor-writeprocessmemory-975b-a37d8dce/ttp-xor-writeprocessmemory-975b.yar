rule TTP_XOR_WriteProcessMemory_975b {
  strings:
    $key_975b = { c0 29 [2] f2 0b [2] f4 3e [2] da 3e [2] e5 22 }

  condition:
    any of them
}