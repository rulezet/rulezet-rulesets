rule TTP_XOR_WriteProcessMemory_b9e8 {
  strings:
    $key_b9e8 = { ee 9a [2] dc b8 [2] da 8d [2] f4 8d [2] cb 91 }

  condition:
    any of them
}