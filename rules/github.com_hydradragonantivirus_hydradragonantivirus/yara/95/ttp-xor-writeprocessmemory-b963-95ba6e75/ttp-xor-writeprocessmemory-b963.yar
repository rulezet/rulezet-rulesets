rule TTP_XOR_WriteProcessMemory_b963 {
  strings:
    $key_b963 = { ee 11 [2] dc 33 [2] da 06 [2] f4 06 [2] cb 1a }

  condition:
    any of them
}