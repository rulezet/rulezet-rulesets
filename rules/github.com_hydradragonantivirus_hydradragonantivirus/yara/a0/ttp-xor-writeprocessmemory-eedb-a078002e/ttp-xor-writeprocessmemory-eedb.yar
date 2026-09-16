rule TTP_XOR_WriteProcessMemory_eedb {
  strings:
    $key_eedb = { b9 a9 [2] 8b 8b [2] 8d be [2] a3 be [2] 9c a2 }

  condition:
    any of them
}