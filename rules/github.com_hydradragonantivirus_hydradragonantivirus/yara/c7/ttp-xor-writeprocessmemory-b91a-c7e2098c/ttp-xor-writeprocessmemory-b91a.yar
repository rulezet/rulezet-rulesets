rule TTP_XOR_WriteProcessMemory_b91a {
  strings:
    $key_b91a = { ee 68 [2] dc 4a [2] da 7f [2] f4 7f [2] cb 63 }

  condition:
    any of them
}