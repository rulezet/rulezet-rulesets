rule TTP_XOR_WriteProcessMemory_b908 {
  strings:
    $key_b908 = { ee 7a [2] dc 58 [2] da 6d [2] f4 6d [2] cb 71 }

  condition:
    any of them
}