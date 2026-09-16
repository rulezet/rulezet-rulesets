rule TTP_XOR_WriteProcessMemory_b91f {
  strings:
    $key_b91f = { ee 6d [2] dc 4f [2] da 7a [2] f4 7a [2] cb 66 }

  condition:
    any of them
}