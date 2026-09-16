rule TTP_XOR_WriteProcessMemory_913e {
  strings:
    $key_913e = { c6 4c [2] f4 6e [2] f2 5b [2] dc 5b [2] e3 47 }

  condition:
    any of them
}