rule TTP_XOR_WriteProcessMemory_b9e2 {
  strings:
    $key_b9e2 = { ee 90 [2] dc b2 [2] da 87 [2] f4 87 [2] cb 9b }

  condition:
    any of them
}