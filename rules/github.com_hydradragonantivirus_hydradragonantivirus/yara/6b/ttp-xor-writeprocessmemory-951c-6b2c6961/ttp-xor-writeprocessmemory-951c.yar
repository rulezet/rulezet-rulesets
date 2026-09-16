rule TTP_XOR_WriteProcessMemory_951c {
  strings:
    $key_951c = { c2 6e [2] f0 4c [2] f6 79 [2] d8 79 [2] e7 65 }

  condition:
    any of them
}