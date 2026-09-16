rule TTP_XOR_WriteProcessMemory_b93e {
  strings:
    $key_b93e = { ee 4c [2] dc 6e [2] da 5b [2] f4 5b [2] cb 47 }

  condition:
    any of them
}