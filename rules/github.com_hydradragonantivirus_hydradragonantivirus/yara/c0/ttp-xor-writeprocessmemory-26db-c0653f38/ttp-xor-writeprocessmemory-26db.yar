rule TTP_XOR_WriteProcessMemory_26db {
  strings:
    $key_26db = { 71 a9 [2] 43 8b [2] 45 be [2] 6b be [2] 54 a2 }

  condition:
    any of them
}