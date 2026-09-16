rule TTP_XOR_WriteProcessMemory_86bc {
  strings:
    $key_86bc = { d1 ce [2] e3 ec [2] e5 d9 [2] cb d9 [2] f4 c5 }

  condition:
    any of them
}