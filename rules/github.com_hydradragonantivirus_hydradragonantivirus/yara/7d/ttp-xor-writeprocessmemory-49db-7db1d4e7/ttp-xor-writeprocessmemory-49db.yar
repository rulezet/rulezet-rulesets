rule TTP_XOR_WriteProcessMemory_49db {
  strings:
    $key_49db = { 1e a9 [2] 2c 8b [2] 2a be [2] 04 be [2] 3b a2 }

  condition:
    any of them
}