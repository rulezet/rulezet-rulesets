rule TTP_XOR_WriteProcessMemory_92db {
  strings:
    $key_92db = { c5 a9 [2] f7 8b [2] f1 be [2] df be [2] e0 a2 }

  condition:
    any of them
}