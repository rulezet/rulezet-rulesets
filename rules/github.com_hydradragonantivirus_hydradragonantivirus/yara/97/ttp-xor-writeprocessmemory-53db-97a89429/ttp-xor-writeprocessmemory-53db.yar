rule TTP_XOR_WriteProcessMemory_53db {
  strings:
    $key_53db = { 04 a9 [2] 36 8b [2] 30 be [2] 1e be [2] 21 a2 }

  condition:
    any of them
}