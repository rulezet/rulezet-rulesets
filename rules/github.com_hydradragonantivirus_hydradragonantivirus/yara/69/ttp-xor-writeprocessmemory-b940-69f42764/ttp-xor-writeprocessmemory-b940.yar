rule TTP_XOR_WriteProcessMemory_b940 {
  strings:
    $key_b940 = { ee 32 [2] dc 10 [2] da 25 [2] f4 25 [2] cb 39 }

  condition:
    any of them
}