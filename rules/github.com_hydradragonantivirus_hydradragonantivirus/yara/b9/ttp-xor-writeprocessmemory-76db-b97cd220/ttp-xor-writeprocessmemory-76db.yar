rule TTP_XOR_WriteProcessMemory_76db {
  strings:
    $key_76db = { 21 a9 [2] 13 8b [2] 15 be [2] 3b be [2] 04 a2 }

  condition:
    any of them
}