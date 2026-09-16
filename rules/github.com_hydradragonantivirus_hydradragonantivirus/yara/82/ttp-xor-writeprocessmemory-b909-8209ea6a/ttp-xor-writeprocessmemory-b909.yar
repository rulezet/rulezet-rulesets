rule TTP_XOR_WriteProcessMemory_b909 {
  strings:
    $key_b909 = { ee 7b [2] dc 59 [2] da 6c [2] f4 6c [2] cb 70 }

  condition:
    any of them
}