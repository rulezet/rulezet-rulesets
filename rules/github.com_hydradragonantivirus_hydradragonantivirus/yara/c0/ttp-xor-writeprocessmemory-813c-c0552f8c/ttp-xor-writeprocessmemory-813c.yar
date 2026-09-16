rule TTP_XOR_WriteProcessMemory_813c {
  strings:
    $key_813c = { d6 4e [2] e4 6c [2] e2 59 [2] cc 59 [2] f3 45 }

  condition:
    any of them
}