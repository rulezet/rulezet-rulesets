rule TTP_XOR_WriteProcessMemory_951e {
  strings:
    $key_951e = { c2 6c [2] f0 4e [2] f6 7b [2] d8 7b [2] e7 67 }

  condition:
    any of them
}