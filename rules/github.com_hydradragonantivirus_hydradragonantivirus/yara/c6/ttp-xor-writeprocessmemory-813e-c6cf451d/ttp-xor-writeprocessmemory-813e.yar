rule TTP_XOR_WriteProcessMemory_813e {
  strings:
    $key_813e = { d6 4c [2] e4 6e [2] e2 5b [2] cc 5b [2] f3 47 }

  condition:
    any of them
}