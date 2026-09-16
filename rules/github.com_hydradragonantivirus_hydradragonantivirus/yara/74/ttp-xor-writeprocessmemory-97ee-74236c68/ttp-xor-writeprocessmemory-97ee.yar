rule TTP_XOR_WriteProcessMemory_97ee {
  strings:
    $key_97ee = { c0 9c [2] f2 be [2] f4 8b [2] da 8b [2] e5 97 }

  condition:
    any of them
}