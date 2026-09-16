rule TTP_XOR_WriteProcessMemory_65db {
  strings:
    $key_65db = { 32 a9 [2] 00 8b [2] 06 be [2] 28 be [2] 17 a2 }

  condition:
    any of them
}