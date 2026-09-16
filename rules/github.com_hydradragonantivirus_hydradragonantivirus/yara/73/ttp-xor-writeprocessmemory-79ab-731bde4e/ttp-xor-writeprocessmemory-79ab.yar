rule TTP_XOR_WriteProcessMemory_79ab {
  strings:
    $key_79ab = { 2e d9 [2] 1c fb [2] 1a ce [2] 34 ce [2] 0b d2 }

  condition:
    any of them
}