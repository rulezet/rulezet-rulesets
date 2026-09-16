rule TTP_XOR_WriteProcessMemory_5fdb {
  strings:
    $key_5fdb = { 08 a9 [2] 3a 8b [2] 3c be [2] 12 be [2] 2d a2 }

  condition:
    any of them
}