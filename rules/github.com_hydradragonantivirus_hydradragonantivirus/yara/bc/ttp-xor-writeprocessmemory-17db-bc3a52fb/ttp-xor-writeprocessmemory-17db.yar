rule TTP_XOR_WriteProcessMemory_17db {
  strings:
    $key_17db = { 40 a9 [2] 72 8b [2] 74 be [2] 5a be [2] 65 a2 }

  condition:
    any of them
}