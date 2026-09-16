rule TTP_XOR_WriteProcessMemory_86db {
  strings:
    $key_86db = { d1 a9 [2] e3 8b [2] e5 be [2] cb be [2] f4 a2 }

  condition:
    any of them
}