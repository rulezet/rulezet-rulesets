rule TTP_XOR_WriteProcessMemory_86ab {
  strings:
    $key_86ab = { d1 d9 [2] e3 fb [2] e5 ce [2] cb ce [2] f4 d2 }

  condition:
    any of them
}