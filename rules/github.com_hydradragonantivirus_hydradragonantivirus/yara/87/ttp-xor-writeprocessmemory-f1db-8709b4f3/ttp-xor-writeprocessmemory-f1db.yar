rule TTP_XOR_WriteProcessMemory_f1db {
  strings:
    $key_f1db = { a6 a9 [2] 94 8b [2] 92 be [2] bc be [2] 83 a2 }

  condition:
    any of them
}