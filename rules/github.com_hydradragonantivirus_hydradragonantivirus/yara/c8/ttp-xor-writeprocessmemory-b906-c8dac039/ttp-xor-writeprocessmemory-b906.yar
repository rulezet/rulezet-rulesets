rule TTP_XOR_WriteProcessMemory_b906 {
  strings:
    $key_b906 = { ee 74 [2] dc 56 [2] da 63 [2] f4 63 [2] cb 7f }

  condition:
    any of them
}