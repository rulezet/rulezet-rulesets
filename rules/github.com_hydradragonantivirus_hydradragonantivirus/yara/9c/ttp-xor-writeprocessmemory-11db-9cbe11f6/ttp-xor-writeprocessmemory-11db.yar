rule TTP_XOR_WriteProcessMemory_11db {
  strings:
    $key_11db = { 46 a9 [2] 74 8b [2] 72 be [2] 5c be [2] 63 a2 }

  condition:
    any of them
}