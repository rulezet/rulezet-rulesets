rule TTP_XOR_WriteProcessMemory_b9ff {
  strings:
    $key_b9ff = { ee 8d [2] dc af [2] da 9a [2] f4 9a [2] cb 86 }

  condition:
    any of them
}