rule TTP_XOR_WriteProcessMemory_910c {
  strings:
    $key_910c = { c6 7e [2] f4 5c [2] f2 69 [2] dc 69 [2] e3 75 }

  condition:
    any of them
}