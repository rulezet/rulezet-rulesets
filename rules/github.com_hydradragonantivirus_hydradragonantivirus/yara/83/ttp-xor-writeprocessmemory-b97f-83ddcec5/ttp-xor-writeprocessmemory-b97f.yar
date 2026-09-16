rule TTP_XOR_WriteProcessMemory_b97f {
  strings:
    $key_b97f = { ee 0d [2] dc 2f [2] da 1a [2] f4 1a [2] cb 06 }

  condition:
    any of them
}