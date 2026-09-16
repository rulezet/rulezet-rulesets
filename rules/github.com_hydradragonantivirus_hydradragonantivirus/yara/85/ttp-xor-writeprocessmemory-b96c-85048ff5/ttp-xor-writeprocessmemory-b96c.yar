rule TTP_XOR_WriteProcessMemory_b96c {
  strings:
    $key_b96c = { ee 1e [2] dc 3c [2] da 09 [2] f4 09 [2] cb 15 }

  condition:
    any of them
}