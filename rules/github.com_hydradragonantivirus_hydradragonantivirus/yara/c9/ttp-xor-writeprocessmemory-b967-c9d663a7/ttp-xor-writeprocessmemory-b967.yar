rule TTP_XOR_WriteProcessMemory_b967 {
  strings:
    $key_b967 = { ee 15 [2] dc 37 [2] da 02 [2] f4 02 [2] cb 1e }

  condition:
    any of them
}