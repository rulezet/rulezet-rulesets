rule TTP_XOR_WriteProcessMemory_13db {
  strings:
    $key_13db = { 44 a9 [2] 76 8b [2] 70 be [2] 5e be [2] 61 a2 }

  condition:
    any of them
}