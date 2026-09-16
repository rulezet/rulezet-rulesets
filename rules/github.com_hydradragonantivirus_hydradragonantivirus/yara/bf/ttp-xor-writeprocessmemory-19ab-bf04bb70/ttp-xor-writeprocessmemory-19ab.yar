rule TTP_XOR_WriteProcessMemory_19ab {
  strings:
    $key_19ab = { 4e d9 [2] 7c fb [2] 7a ce [2] 54 ce [2] 6b d2 }

  condition:
    any of them
}