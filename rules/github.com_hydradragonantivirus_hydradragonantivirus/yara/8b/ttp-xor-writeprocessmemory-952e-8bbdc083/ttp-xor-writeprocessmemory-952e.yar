rule TTP_XOR_WriteProcessMemory_952e {
  strings:
    $key_952e = { c2 5c [2] f0 7e [2] f6 4b [2] d8 4b [2] e7 57 }

  condition:
    any of them
}