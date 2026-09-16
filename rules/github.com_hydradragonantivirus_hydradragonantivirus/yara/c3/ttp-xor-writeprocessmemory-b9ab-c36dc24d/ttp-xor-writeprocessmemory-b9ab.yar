rule TTP_XOR_WriteProcessMemory_b9ab {
  strings:
    $key_b9ab = { ee d9 [2] dc fb [2] da ce [2] f4 ce [2] cb d2 }

  condition:
    any of them
}