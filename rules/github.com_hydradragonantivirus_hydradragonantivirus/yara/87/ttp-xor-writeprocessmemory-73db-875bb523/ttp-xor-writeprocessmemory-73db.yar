rule TTP_XOR_WriteProcessMemory_73db {
  strings:
    $key_73db = { 24 a9 [2] 16 8b [2] 10 be [2] 3e be [2] 01 a2 }

  condition:
    any of them
}