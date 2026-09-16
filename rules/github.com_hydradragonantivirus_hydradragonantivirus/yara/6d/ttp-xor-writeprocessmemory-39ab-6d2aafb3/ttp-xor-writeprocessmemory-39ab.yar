rule TTP_XOR_WriteProcessMemory_39ab {
  strings:
    $key_39ab = { 6e d9 [2] 5c fb [2] 5a ce [2] 74 ce [2] 4b d2 }

  condition:
    any of them
}