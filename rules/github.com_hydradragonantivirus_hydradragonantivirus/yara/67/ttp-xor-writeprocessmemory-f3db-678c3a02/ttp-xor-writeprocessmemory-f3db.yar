rule TTP_XOR_WriteProcessMemory_f3db {
  strings:
    $key_f3db = { a4 a9 [2] 96 8b [2] 90 be [2] be be [2] 81 a2 }

  condition:
    any of them
}