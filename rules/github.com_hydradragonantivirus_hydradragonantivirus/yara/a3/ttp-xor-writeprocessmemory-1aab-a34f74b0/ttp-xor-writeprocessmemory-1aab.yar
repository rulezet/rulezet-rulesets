rule TTP_XOR_WriteProcessMemory_1aab {
  strings:
    $key_1aab = { 4d d9 [2] 7f fb [2] 79 ce [2] 57 ce [2] 68 d2 }

  condition:
    any of them
}