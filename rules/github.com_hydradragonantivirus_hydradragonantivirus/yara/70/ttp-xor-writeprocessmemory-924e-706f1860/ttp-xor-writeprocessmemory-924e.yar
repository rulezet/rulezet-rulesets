rule TTP_XOR_WriteProcessMemory_924e {
  strings:
    $key_924e = { c5 3c [2] f7 1e [2] f1 2b [2] df 2b [2] e0 37 }

  condition:
    any of them
}