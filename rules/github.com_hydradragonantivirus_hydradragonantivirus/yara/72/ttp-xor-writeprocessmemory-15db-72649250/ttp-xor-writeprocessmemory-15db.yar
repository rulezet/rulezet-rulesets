rule TTP_XOR_WriteProcessMemory_15db {
  strings:
    $key_15db = { 42 a9 [2] 70 8b [2] 76 be [2] 58 be [2] 67 a2 }

  condition:
    any of them
}