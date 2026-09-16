rule TTP_XOR_WriteProcessMemory_920b {
  strings:
    $key_920b = { c5 79 [2] f7 5b [2] f1 6e [2] df 6e [2] e0 72 }

  condition:
    any of them
}