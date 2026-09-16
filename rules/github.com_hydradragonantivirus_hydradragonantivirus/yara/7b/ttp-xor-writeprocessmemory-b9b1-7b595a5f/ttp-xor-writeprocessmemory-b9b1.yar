rule TTP_XOR_WriteProcessMemory_b9b1 {
  strings:
    $key_b9b1 = { ee c3 [2] dc e1 [2] da d4 [2] f4 d4 [2] cb c8 }

  condition:
    any of them
}