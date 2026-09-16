rule TTP_XOR_WriteProcessMemory_1edb {
  strings:
    $key_1edb = { 49 a9 [2] 7b 8b [2] 7d be [2] 53 be [2] 6c a2 }

  condition:
    any of them
}