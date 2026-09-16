rule TTP_XOR_WriteProcessMemory_b8ab {
  strings:
    $key_b8ab = { ef d9 [2] dd fb [2] db ce [2] f5 ce [2] ca d2 }

  condition:
    any of them
}