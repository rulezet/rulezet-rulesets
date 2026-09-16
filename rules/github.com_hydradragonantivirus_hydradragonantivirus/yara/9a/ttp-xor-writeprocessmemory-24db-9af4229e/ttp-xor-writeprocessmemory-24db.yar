rule TTP_XOR_WriteProcessMemory_24db {
  strings:
    $key_24db = { 73 a9 [2] 41 8b [2] 47 be [2] 69 be [2] 56 a2 }

  condition:
    any of them
}