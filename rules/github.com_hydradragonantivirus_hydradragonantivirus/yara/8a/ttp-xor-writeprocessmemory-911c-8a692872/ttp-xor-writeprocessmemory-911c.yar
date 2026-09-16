rule TTP_XOR_WriteProcessMemory_911c {
  strings:
    $key_911c = { c6 6e [2] f4 4c [2] f2 79 [2] dc 79 [2] e3 65 }

  condition:
    any of them
}