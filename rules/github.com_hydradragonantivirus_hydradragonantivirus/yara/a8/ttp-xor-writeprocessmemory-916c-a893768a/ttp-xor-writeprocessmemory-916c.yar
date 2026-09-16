rule TTP_XOR_WriteProcessMemory_916c {
  strings:
    $key_916c = { c6 1e [2] f4 3c [2] f2 09 [2] dc 09 [2] e3 15 }

  condition:
    any of them
}