rule TTP_XOR_WriteProcessMemory_16db {
  strings:
    $key_16db = { 41 a9 [2] 73 8b [2] 75 be [2] 5b be [2] 64 a2 }

  condition:
    any of them
}