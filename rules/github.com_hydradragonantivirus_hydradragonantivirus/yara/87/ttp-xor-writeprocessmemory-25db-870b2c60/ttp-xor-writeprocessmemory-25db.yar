rule TTP_XOR_WriteProcessMemory_25db {
  strings:
    $key_25db = { 72 a9 [2] 40 8b [2] 46 be [2] 68 be [2] 57 a2 }

  condition:
    any of them
}