rule TTP_XOR_WriteProcessMemory_b918 {
  strings:
    $key_b918 = { ee 6a [2] dc 48 [2] da 7d [2] f4 7d [2] cb 61 }

  condition:
    any of them
}