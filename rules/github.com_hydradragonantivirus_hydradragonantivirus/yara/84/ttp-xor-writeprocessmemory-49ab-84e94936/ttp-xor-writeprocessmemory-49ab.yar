rule TTP_XOR_WriteProcessMemory_49ab {
  strings:
    $key_49ab = { 1e d9 [2] 2c fb [2] 2a ce [2] 04 ce [2] 3b d2 }

  condition:
    any of them
}