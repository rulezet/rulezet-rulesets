rule TTP_XOR_WriteProcessMemory_b9e6 {
  strings:
    $key_b9e6 = { ee 94 [2] dc b6 [2] da 83 [2] f4 83 [2] cb 9f }

  condition:
    any of them
}