rule TTP_XOR_WriteProcessMemory_925c {
  strings:
    $key_925c = { c5 2e [2] f7 0c [2] f1 39 [2] df 39 [2] e0 25 }

  condition:
    any of them
}