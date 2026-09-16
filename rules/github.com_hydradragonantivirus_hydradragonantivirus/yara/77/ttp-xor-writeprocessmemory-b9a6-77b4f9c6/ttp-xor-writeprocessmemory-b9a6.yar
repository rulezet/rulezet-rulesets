rule TTP_XOR_WriteProcessMemory_b9a6 {
  strings:
    $key_b9a6 = { ee d4 [2] dc f6 [2] da c3 [2] f4 c3 [2] cb df }

  condition:
    any of them
}