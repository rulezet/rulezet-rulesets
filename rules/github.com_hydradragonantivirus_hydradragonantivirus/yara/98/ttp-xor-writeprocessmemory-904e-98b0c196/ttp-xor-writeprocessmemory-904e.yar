rule TTP_XOR_WriteProcessMemory_904e {
  strings:
    $key_904e = { c7 3c [2] f5 1e [2] f3 2b [2] dd 2b [2] e2 37 }

  condition:
    any of them
}