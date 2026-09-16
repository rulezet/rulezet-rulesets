rule TTP_XOR_WriteProcessMemory_b96a {
  strings:
    $key_b96a = { ee 18 [2] dc 3a [2] da 0f [2] f4 0f [2] cb 13 }

  condition:
    any of them
}