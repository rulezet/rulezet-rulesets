rule TTP_XOR_WriteProcessMemory_81db {
  strings:
    $key_81db = { d6 a9 [2] e4 8b [2] e2 be [2] cc be [2] f3 a2 }

  condition:
    any of them
}