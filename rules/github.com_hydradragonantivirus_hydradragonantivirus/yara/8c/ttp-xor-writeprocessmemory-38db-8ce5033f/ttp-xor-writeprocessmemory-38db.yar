rule TTP_XOR_WriteProcessMemory_38db {
  strings:
    $key_38db = { 6f a9 [2] 5d 8b [2] 5b be [2] 75 be [2] 4a a2 }

  condition:
    any of them
}