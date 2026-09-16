rule TTP_XOR_WriteProcessMemory_b90d {
  strings:
    $key_b90d = { ee 7f [2] dc 5d [2] da 68 [2] f4 68 [2] cb 74 }

  condition:
    any of them
}