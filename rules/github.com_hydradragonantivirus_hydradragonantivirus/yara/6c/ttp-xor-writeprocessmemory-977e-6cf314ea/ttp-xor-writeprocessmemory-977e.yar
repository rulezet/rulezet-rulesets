rule TTP_XOR_WriteProcessMemory_977e {
  strings:
    $key_977e = { c0 0c [2] f2 2e [2] f4 1b [2] da 1b [2] e5 07 }

  condition:
    any of them
}