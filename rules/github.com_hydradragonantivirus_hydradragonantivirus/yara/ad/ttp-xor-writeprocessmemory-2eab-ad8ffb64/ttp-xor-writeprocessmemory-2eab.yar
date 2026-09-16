rule TTP_XOR_WriteProcessMemory_2eab {
  strings:
    $key_2eab = { 79 d9 [2] 4b fb [2] 4d ce [2] 63 ce [2] 5c d2 }

  condition:
    any of them
}