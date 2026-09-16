rule TTP_XOR_WriteProcessMemory_2cab {
  strings:
    $key_2cab = { 7b d9 [2] 49 fb [2] 4f ce [2] 61 ce [2] 5e d2 }

  condition:
    any of them
}