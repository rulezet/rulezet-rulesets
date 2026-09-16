rule TTP_XOR_WriteProcessMemory_50db {
  strings:
    $key_50db = { 07 a9 [2] 35 8b [2] 33 be [2] 1d be [2] 22 a2 }

  condition:
    any of them
}