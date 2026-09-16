rule TTP_XOR_WriteProcessMemory_0bdb {
  strings:
    $key_0bdb = { 5c a9 [2] 6e 8b [2] 68 be [2] 46 be [2] 79 a2 }

  condition:
    any of them
}