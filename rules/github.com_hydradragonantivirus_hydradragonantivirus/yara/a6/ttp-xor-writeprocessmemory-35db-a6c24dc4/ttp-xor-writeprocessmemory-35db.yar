rule TTP_XOR_WriteProcessMemory_35db {
  strings:
    $key_35db = { 62 a9 [2] 50 8b [2] 56 be [2] 78 be [2] 47 a2 }

  condition:
    any of them
}