rule TTP_XOR_WriteProcessMemory_816b {
  strings:
    $key_816b = { d6 19 [2] e4 3b [2] e2 0e [2] cc 0e [2] f3 12 }

  condition:
    any of them
}