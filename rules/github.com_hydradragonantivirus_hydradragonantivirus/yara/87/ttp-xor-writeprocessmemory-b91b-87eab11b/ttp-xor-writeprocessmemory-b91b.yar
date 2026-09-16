rule TTP_XOR_WriteProcessMemory_b91b {
  strings:
    $key_b91b = { ee 69 [2] dc 4b [2] da 7e [2] f4 7e [2] cb 62 }

  condition:
    any of them
}