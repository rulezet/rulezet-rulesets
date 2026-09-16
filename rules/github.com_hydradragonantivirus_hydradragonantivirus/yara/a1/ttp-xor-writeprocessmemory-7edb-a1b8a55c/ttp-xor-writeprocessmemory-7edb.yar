rule TTP_XOR_WriteProcessMemory_7edb {
  strings:
    $key_7edb = { 29 a9 [2] 1b 8b [2] 1d be [2] 33 be [2] 0c a2 }

  condition:
    any of them
}