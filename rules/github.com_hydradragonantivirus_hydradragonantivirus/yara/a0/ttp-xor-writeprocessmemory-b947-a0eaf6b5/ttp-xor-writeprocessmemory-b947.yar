rule TTP_XOR_WriteProcessMemory_b947 {
  strings:
    $key_b947 = { ee 35 [2] dc 17 [2] da 22 [2] f4 22 [2] cb 3e }

  condition:
    any of them
}