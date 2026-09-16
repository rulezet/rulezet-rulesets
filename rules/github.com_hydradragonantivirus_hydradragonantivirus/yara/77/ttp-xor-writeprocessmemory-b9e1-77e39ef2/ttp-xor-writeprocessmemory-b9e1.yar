rule TTP_XOR_WriteProcessMemory_b9e1 {
  strings:
    $key_b9e1 = { ee 93 [2] dc b1 [2] da 84 [2] f4 84 [2] cb 98 }

  condition:
    any of them
}