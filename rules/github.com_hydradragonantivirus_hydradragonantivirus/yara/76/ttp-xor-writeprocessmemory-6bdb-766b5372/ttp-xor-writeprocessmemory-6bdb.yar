rule TTP_XOR_WriteProcessMemory_6bdb {
  strings:
    $key_6bdb = { 3c a9 [2] 0e 8b [2] 08 be [2] 26 be [2] 19 a2 }

  condition:
    any of them
}