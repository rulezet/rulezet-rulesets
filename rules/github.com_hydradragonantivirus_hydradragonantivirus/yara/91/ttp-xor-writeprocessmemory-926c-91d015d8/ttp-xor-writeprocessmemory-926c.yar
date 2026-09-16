rule TTP_XOR_WriteProcessMemory_926c {
  strings:
    $key_926c = { c5 1e [2] f7 3c [2] f1 09 [2] df 09 [2] e0 15 }

  condition:
    any of them
}