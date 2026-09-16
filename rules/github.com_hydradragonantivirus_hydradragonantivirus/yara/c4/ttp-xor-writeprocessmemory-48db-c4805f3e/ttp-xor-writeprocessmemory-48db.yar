rule TTP_XOR_WriteProcessMemory_48db {
  strings:
    $key_48db = { 1f a9 [2] 2d 8b [2] 2b be [2] 05 be [2] 3a a2 }

  condition:
    any of them
}