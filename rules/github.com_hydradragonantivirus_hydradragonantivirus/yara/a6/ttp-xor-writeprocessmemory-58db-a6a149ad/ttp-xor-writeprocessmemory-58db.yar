rule TTP_XOR_WriteProcessMemory_58db {
  strings:
    $key_58db = { 0f a9 [2] 3d 8b [2] 3b be [2] 15 be [2] 2a a2 }

  condition:
    any of them
}