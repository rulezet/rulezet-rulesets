rule TTP_XOR_WriteProcessMemory_b972 {
  strings:
    $key_b972 = { ee 00 [2] dc 22 [2] da 17 [2] f4 17 [2] cb 0b }

  condition:
    any of them
}