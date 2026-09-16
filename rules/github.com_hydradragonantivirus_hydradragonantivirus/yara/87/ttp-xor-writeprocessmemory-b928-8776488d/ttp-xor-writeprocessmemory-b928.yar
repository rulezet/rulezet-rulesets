rule TTP_XOR_WriteProcessMemory_b928 {
  strings:
    $key_b928 = { ee 5a [2] dc 78 [2] da 4d [2] f4 4d [2] cb 51 }

  condition:
    any of them
}