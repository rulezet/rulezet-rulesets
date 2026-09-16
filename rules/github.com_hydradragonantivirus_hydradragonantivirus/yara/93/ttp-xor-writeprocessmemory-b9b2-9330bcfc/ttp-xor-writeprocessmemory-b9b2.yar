rule TTP_XOR_WriteProcessMemory_b9b2 {
  strings:
    $key_b9b2 = { ee c0 [2] dc e2 [2] da d7 [2] f4 d7 [2] cb cb }

  condition:
    any of them
}