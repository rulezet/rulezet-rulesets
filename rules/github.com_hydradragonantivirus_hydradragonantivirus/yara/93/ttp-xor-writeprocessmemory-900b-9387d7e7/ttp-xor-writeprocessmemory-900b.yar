rule TTP_XOR_WriteProcessMemory_900b {
  strings:
    $key_900b = { c7 79 [2] f5 5b [2] f3 6e [2] dd 6e [2] e2 72 }

  condition:
    any of them
}