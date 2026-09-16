rule TTP_XOR_WriteProcessMemory_b985 {
  strings:
    $key_b985 = { ee f7 [2] dc d5 [2] da e0 [2] f4 e0 [2] cb fc }

  condition:
    any of them
}