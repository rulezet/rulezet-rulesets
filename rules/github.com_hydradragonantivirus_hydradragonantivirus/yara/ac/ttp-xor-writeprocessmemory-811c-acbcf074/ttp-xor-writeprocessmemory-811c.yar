rule TTP_XOR_WriteProcessMemory_811c {
  strings:
    $key_811c = { d6 6e [2] e4 4c [2] e2 79 [2] cc 79 [2] f3 65 }

  condition:
    any of them
}