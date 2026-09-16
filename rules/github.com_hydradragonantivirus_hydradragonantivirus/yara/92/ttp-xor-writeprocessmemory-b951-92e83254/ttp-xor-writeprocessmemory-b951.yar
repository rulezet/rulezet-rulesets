rule TTP_XOR_WriteProcessMemory_b951 {
  strings:
    $key_b951 = { ee 23 [2] dc 01 [2] da 34 [2] f4 34 [2] cb 28 }

  condition:
    any of them
}