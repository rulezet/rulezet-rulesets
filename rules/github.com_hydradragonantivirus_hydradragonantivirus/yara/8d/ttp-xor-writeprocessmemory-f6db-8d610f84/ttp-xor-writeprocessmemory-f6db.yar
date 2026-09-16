rule TTP_XOR_WriteProcessMemory_f6db {
  strings:
    $key_f6db = { a1 a9 [2] 93 8b [2] 95 be [2] bb be [2] 84 a2 }

  condition:
    any of them
}