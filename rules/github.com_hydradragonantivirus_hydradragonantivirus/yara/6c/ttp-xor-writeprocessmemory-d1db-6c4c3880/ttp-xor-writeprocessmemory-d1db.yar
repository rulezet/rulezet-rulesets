rule TTP_XOR_WriteProcessMemory_d1db {
  strings:
    $key_d1db = { 86 a9 [2] b4 8b [2] b2 be [2] 9c be [2] a3 a2 }

  condition:
    any of them
}