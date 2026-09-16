rule TTP_XOR_WriteProcessMemory_4aab {
  strings:
    $key_4aab = { 1d d9 [2] 2f fb [2] 29 ce [2] 07 ce [2] 38 d2 }

  condition:
    any of them
}