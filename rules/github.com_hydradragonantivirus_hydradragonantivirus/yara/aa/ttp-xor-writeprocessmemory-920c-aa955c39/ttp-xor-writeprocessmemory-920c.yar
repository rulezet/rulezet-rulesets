rule TTP_XOR_WriteProcessMemory_920c {
  strings:
    $key_920c = { c5 7e [2] f7 5c [2] f1 69 [2] df 69 [2] e0 75 }

  condition:
    any of them
}