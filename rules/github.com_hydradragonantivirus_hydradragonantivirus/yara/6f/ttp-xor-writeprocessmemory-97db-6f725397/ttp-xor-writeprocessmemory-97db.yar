rule TTP_XOR_WriteProcessMemory_97db {
  strings:
    $key_97db = { c0 a9 [2] f2 8b [2] f4 be [2] da be [2] e5 a2 }

  condition:
    any of them
}