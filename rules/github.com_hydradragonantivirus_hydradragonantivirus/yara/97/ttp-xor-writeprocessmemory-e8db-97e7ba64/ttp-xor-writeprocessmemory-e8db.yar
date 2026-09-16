rule TTP_XOR_WriteProcessMemory_e8db {
  strings:
    $key_e8db = { bf a9 [2] 8d 8b [2] 8b be [2] a5 be [2] 9a a2 }

  condition:
    any of them
}