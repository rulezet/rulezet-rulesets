rule TTP_XOR_WriteProcessMemory_4cab {
  strings:
    $key_4cab = { 1b d9 [2] 29 fb [2] 2f ce [2] 01 ce [2] 3e d2 }

  condition:
    any of them
}