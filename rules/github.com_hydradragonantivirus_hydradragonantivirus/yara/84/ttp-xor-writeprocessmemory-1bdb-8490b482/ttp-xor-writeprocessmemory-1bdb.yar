rule TTP_XOR_WriteProcessMemory_1bdb {
  strings:
    $key_1bdb = { 4c a9 [2] 7e 8b [2] 78 be [2] 56 be [2] 69 a2 }

  condition:
    any of them
}