rule TTP_XOR_WriteProcessMemory_78db {
  strings:
    $key_78db = { 2f a9 [2] 1d 8b [2] 1b be [2] 35 be [2] 0a a2 }

  condition:
    any of them
}