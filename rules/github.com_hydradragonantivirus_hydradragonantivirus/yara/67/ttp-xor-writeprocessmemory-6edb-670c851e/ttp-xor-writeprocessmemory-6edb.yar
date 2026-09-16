rule TTP_XOR_WriteProcessMemory_6edb {
  strings:
    $key_6edb = { 39 a9 [2] 0b 8b [2] 0d be [2] 23 be [2] 1c a2 }

  condition:
    any of them
}