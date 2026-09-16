rule TTP_XOR_WriteProcessMemory_0fdb {
  strings:
    $key_0fdb = { 58 a9 [2] 6a 8b [2] 6c be [2] 42 be [2] 7d a2 }

  condition:
    any of them
}