rule TTP_XOR_WriteProcessMemory_b982 {
  strings:
    $key_b982 = { ee f0 [2] dc d2 [2] da e7 [2] f4 e7 [2] cb fb }

  condition:
    any of them
}