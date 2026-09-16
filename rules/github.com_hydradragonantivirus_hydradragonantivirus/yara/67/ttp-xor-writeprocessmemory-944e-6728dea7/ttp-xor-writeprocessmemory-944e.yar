rule TTP_XOR_WriteProcessMemory_944e {
  strings:
    $key_944e = { c3 3c [2] f1 1e [2] f7 2b [2] d9 2b [2] e6 37 }

  condition:
    any of them
}