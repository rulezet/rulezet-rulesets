rule TTP_XOR_WriteProcessMemory_903e {
  strings:
    $key_903e = { c7 4c [2] f5 6e [2] f3 5b [2] dd 5b [2] e2 47 }

  condition:
    any of them
}