rule TTP_XOR_WriteProcessMemory_52db {
  strings:
    $key_52db = { 05 a9 [2] 37 8b [2] 31 be [2] 1f be [2] 20 a2 }

  condition:
    any of them
}