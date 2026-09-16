rule TTP_XOR_WriteProcessMemory_0cab {
  strings:
    $key_0cab = { 5b d9 [2] 69 fb [2] 6f ce [2] 41 ce [2] 7e d2 }

  condition:
    any of them
}