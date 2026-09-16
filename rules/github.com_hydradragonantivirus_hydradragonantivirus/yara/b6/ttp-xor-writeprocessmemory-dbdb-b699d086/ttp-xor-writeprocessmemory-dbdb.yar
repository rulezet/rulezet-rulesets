rule TTP_XOR_WriteProcessMemory_dbdb {
  strings:
    $key_dbdb = { 8c a9 [2] be 8b [2] b8 be [2] 96 be [2] a9 a2 }

  condition:
    any of them
}