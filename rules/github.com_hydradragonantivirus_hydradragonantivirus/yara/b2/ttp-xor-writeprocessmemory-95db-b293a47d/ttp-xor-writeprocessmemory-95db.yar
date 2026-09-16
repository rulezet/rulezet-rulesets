rule TTP_XOR_WriteProcessMemory_95db {
  strings:
    $key_95db = { c2 a9 [2] f0 8b [2] f6 be [2] d8 be [2] e7 a2 }

  condition:
    any of them
}