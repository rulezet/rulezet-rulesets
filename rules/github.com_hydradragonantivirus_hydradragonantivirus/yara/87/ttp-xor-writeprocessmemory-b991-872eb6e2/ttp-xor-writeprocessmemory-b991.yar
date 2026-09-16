rule TTP_XOR_WriteProcessMemory_b991 {
  strings:
    $key_b991 = { ee e3 [2] dc c1 [2] da f4 [2] f4 f4 [2] cb e8 }

  condition:
    any of them
}