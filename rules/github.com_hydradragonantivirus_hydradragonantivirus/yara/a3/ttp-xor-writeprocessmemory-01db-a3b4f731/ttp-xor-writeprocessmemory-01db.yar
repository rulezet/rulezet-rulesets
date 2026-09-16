rule TTP_XOR_WriteProcessMemory_01db {
  strings:
    $key_01db = { 56 a9 [2] 64 8b [2] 62 be [2] 4c be [2] 73 a2 }

  condition:
    any of them
}