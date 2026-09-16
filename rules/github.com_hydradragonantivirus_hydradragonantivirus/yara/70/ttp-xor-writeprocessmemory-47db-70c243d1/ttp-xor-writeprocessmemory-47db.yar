rule TTP_XOR_WriteProcessMemory_47db {
  strings:
    $key_47db = { 10 a9 [2] 22 8b [2] 24 be [2] 0a be [2] 35 a2 }

  condition:
    any of them
}