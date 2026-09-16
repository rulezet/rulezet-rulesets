rule TTP_XOR_WriteProcessMemory_a5db {
  strings:
    $key_a5db = { f2 a9 [2] c0 8b [2] c6 be [2] e8 be [2] d7 a2 }

  condition:
    any of them
}