rule TTP_XOR_WriteProcessMemory_46db {
  strings:
    $key_46db = { 11 a9 [2] 23 8b [2] 25 be [2] 0b be [2] 34 a2 }

  condition:
    any of them
}