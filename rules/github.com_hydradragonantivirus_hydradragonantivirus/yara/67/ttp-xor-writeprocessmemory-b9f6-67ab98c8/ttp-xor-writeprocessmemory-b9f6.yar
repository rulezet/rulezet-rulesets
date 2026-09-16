rule TTP_XOR_WriteProcessMemory_b9f6 {
  strings:
    $key_b9f6 = { ee 84 [2] dc a6 [2] da 93 [2] f4 93 [2] cb 8f }

  condition:
    any of them
}