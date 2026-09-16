rule TTP_XOR_WriteProcessMemory_954e {
  strings:
    $key_954e = { c2 3c [2] f0 1e [2] f6 2b [2] d8 2b [2] e7 37 }

  condition:
    any of them
}