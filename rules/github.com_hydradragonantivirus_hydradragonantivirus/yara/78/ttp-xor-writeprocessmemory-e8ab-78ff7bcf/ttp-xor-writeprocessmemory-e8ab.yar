rule TTP_XOR_WriteProcessMemory_e8ab {
  strings:
    $key_e8ab = { bf d9 [2] 8d fb [2] 8b ce [2] a5 ce [2] 9a d2 }

  condition:
    any of them
}