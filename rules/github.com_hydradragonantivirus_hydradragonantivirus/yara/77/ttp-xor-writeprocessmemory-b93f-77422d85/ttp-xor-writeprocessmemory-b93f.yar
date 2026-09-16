rule TTP_XOR_WriteProcessMemory_b93f {
  strings:
    $key_b93f = { ee 4d [2] dc 6f [2] da 5a [2] f4 5a [2] cb 46 }

  condition:
    any of them
}