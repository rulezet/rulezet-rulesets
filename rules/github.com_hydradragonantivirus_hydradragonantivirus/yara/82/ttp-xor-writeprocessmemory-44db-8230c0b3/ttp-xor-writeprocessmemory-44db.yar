rule TTP_XOR_WriteProcessMemory_44db {
  strings:
    $key_44db = { 13 a9 [2] 21 8b [2] 27 be [2] 09 be [2] 36 a2 }

  condition:
    any of them
}