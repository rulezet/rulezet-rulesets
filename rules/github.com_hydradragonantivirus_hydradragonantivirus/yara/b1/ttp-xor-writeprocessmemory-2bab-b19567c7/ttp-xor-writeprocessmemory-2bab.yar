rule TTP_XOR_WriteProcessMemory_2bab {
  strings:
    $key_2bab = { 7c d9 [2] 4e fb [2] 48 ce [2] 66 ce [2] 59 d2 }

  condition:
    any of them
}