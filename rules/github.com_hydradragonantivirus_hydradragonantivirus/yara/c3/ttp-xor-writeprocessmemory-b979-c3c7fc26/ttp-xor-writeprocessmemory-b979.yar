rule TTP_XOR_WriteProcessMemory_b979 {
  strings:
    $key_b979 = { ee 0b [2] dc 29 [2] da 1c [2] f4 1c [2] cb 00 }

  condition:
    any of them
}