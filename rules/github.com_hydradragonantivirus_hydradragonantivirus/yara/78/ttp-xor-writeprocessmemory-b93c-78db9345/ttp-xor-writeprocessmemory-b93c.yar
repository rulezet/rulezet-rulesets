rule TTP_XOR_WriteProcessMemory_b93c {
  strings:
    $key_b93c = { ee 4e [2] dc 6c [2] da 59 [2] f4 59 [2] cb 45 }

  condition:
    any of them
}