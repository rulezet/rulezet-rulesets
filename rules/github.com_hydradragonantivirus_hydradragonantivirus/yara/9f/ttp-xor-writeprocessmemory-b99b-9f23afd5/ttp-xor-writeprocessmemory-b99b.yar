rule TTP_XOR_WriteProcessMemory_b99b {
  strings:
    $key_b99b = { ee e9 [2] dc cb [2] da fe [2] f4 fe [2] cb e2 }

  condition:
    any of them
}