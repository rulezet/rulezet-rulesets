rule TTP_XOR_WriteProcessMemory_d7db {
  strings:
    $key_d7db = { 80 a9 [2] b2 8b [2] b4 be [2] 9a be [2] a5 a2 }

  condition:
    any of them
}