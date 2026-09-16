rule TTP_XOR_WriteProcessMemory_f7db {
  strings:
    $key_f7db = { a0 a9 [2] 92 8b [2] 94 be [2] ba be [2] 85 a2 }

  condition:
    any of them
}