rule TTP_XOR_WriteProcessMemory_5aab {
  strings:
    $key_5aab = { 0d d9 [2] 3f fb [2] 39 ce [2] 17 ce [2] 28 d2 }

  condition:
    any of them
}