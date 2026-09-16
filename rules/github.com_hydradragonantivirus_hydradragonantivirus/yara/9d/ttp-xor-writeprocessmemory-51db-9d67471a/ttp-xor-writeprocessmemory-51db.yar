rule TTP_XOR_WriteProcessMemory_51db {
  strings:
    $key_51db = { 06 a9 [2] 34 8b [2] 32 be [2] 1c be [2] 23 a2 }

  condition:
    any of them
}