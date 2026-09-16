rule TTP_XOR_WriteProcessMemory_ecab {
  strings:
    $key_ecab = { bb d9 [2] 89 fb [2] 8f ce [2] a1 ce [2] 9e d2 }

  condition:
    any of them
}