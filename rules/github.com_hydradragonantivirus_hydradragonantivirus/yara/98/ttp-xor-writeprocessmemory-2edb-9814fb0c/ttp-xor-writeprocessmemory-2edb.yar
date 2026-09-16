rule TTP_XOR_WriteProcessMemory_2edb {
  strings:
    $key_2edb = { 79 a9 [2] 4b 8b [2] 4d be [2] 63 be [2] 5c a2 }

  condition:
    any of them
}