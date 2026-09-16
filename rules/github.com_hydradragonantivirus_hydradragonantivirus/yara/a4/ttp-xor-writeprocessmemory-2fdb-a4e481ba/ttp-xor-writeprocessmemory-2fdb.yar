rule TTP_XOR_WriteProcessMemory_2fdb {
  strings:
    $key_2fdb = { 78 a9 [2] 4a 8b [2] 4c be [2] 62 be [2] 5d a2 }

  condition:
    any of them
}