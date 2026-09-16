rule TTP_XOR_WriteProcessMemory_67db {
  strings:
    $key_67db = { 30 a9 [2] 02 8b [2] 04 be [2] 2a be [2] 15 a2 }

  condition:
    any of them
}