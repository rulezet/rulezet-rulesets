rule TTP_XOR_WriteProcessMemory_b930 {
  strings:
    $key_b930 = { ee 42 [2] dc 60 [2] da 55 [2] f4 55 [2] cb 49 }

  condition:
    any of them
}