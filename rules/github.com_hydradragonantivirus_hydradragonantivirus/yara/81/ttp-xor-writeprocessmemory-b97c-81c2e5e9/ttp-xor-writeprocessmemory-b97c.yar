rule TTP_XOR_WriteProcessMemory_b97c {
  strings:
    $key_b97c = { ee 0e [2] dc 2c [2] da 19 [2] f4 19 [2] cb 05 }

  condition:
    any of them
}