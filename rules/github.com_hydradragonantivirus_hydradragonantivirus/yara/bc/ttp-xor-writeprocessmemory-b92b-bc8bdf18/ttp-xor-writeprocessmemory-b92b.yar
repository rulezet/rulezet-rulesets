rule TTP_XOR_WriteProcessMemory_b92b {
  strings:
    $key_b92b = { ee 59 [2] dc 7b [2] da 4e [2] f4 4e [2] cb 52 }

  condition:
    any of them
}