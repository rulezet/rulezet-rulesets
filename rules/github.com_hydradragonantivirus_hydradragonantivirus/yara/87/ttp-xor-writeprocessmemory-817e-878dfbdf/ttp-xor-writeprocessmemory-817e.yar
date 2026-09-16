rule TTP_XOR_WriteProcessMemory_817e {
  strings:
    $key_817e = { d6 0c [2] e4 2e [2] e2 1b [2] cc 1b [2] f3 07 }

  condition:
    any of them
}