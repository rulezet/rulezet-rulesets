rule TTP_XOR_WriteProcessMemory_7fdb {
  strings:
    $key_7fdb = { 28 a9 [2] 1a 8b [2] 1c be [2] 32 be [2] 0d a2 }

  condition:
    any of them
}