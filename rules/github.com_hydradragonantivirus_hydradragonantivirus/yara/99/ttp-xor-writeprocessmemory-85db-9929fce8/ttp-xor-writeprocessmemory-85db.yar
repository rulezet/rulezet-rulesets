rule TTP_XOR_WriteProcessMemory_85db {
  strings:
    $key_85db = { d2 a9 [2] e0 8b [2] e6 be [2] c8 be [2] f7 a2 }

  condition:
    any of them
}