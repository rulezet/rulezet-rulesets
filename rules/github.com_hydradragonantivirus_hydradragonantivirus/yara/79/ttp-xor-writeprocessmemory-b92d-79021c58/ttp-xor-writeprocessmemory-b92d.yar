rule TTP_XOR_WriteProcessMemory_b92d {
  strings:
    $key_b92d = { ee 5f [2] dc 7d [2] da 48 [2] f4 48 [2] cb 54 }

  condition:
    any of them
}