rule TTP_XOR_WriteProcessMemory_911e {
  strings:
    $key_911e = { c6 6c [2] f4 4e [2] f2 7b [2] dc 7b [2] e3 67 }

  condition:
    any of them
}