rule TTP_XOR_WriteProcessMemory_31db {
  strings:
    $key_31db = { 66 a9 [2] 54 8b [2] 52 be [2] 7c be [2] 43 a2 }

  condition:
    any of them
}