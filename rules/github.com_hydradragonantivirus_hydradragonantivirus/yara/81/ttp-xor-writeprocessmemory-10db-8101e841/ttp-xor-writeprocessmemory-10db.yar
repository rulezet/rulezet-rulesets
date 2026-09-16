rule TTP_XOR_WriteProcessMemory_10db {
  strings:
    $key_10db = { 47 a9 [2] 75 8b [2] 73 be [2] 5d be [2] 62 a2 }

  condition:
    any of them
}