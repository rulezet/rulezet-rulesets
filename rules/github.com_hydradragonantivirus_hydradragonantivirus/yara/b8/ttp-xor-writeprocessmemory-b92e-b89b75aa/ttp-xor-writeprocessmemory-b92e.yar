rule TTP_XOR_WriteProcessMemory_b92e {
  strings:
    $key_b92e = { ee 5c [2] dc 7e [2] da 4b [2] f4 4b [2] cb 57 }

  condition:
    any of them
}