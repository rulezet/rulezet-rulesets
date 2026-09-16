rule TTP_XOR_WriteProcessMemory_b984 {
  strings:
    $key_b984 = { ee f6 [2] dc d4 [2] da e1 [2] f4 e1 [2] cb fd }

  condition:
    any of them
}