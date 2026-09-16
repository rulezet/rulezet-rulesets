rule TTP_XOR_WriteProcessMemory_977c {
  strings:
    $key_977c = { c0 0e [2] f2 2c [2] f4 19 [2] da 19 [2] e5 05 }

  condition:
    any of them
}