rule TTP_XOR_WriteProcessMemory_972c {
  strings:
    $key_972c = { c0 5e [2] f2 7c [2] f4 49 [2] da 49 [2] e5 55 }

  condition:
    any of them
}