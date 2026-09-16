rule TTP_XOR_WriteProcessMemory_b978 {
  strings:
    $key_b978 = { ee 0a [2] dc 28 [2] da 1d [2] f4 1d [2] cb 01 }

  condition:
    any of them
}