rule TTP_XOR_WriteProcessMemory_b1db {
  strings:
    $key_b1db = { e6 a9 [2] d4 8b [2] d2 be [2] fc be [2] c3 a2 }

  condition:
    any of them
}