rule TTP_XOR_WriteProcessMemory_b9ee {
  strings:
    $key_b9ee = { ee 9c [2] dc be [2] da 8b [2] f4 8b [2] cb 97 }

  condition:
    any of them
}