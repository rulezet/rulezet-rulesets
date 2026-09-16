rule TTP_XOR_WriteProcessMemory_b7db {
  strings:
    $key_b7db = { e0 a9 [2] d2 8b [2] d4 be [2] fa be [2] c5 a2 }

  condition:
    any of them
}