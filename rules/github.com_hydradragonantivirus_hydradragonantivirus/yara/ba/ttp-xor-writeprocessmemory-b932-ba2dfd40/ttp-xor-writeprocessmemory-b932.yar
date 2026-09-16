rule TTP_XOR_WriteProcessMemory_b932 {
  strings:
    $key_b932 = { ee 40 [2] dc 62 [2] da 57 [2] f4 57 [2] cb 4b }

  condition:
    any of them
}