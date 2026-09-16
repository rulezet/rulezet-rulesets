rule TTP_XOR_WriteProcessMemory_94db {
  strings:
    $key_94db = { c3 a9 [2] f1 8b [2] f7 be [2] d9 be [2] e6 a2 }

  condition:
    any of them
}