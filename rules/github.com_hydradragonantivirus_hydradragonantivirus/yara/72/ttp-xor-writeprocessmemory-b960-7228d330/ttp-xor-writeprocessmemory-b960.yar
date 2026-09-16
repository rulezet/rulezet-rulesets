rule TTP_XOR_WriteProcessMemory_b960 {
  strings:
    $key_b960 = { ee 12 [2] dc 30 [2] da 05 [2] f4 05 [2] cb 19 }

  condition:
    any of them
}