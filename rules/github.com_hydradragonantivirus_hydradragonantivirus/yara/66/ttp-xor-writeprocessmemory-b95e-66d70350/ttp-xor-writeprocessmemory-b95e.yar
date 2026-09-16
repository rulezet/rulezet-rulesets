rule TTP_XOR_WriteProcessMemory_b95e {
  strings:
    $key_b95e = { ee 2c [2] dc 0e [2] da 3b [2] f4 3b [2] cb 27 }

  condition:
    any of them
}