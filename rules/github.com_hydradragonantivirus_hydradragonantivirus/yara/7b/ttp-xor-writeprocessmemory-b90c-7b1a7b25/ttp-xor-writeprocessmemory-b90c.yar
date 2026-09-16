rule TTP_XOR_WriteProcessMemory_b90c {
  strings:
    $key_b90c = { ee 7e [2] dc 5c [2] da 69 [2] f4 69 [2] cb 75 }

  condition:
    any of them
}