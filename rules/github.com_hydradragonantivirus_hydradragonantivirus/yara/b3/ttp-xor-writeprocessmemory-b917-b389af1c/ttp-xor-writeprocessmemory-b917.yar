rule TTP_XOR_WriteProcessMemory_b917 {
  strings:
    $key_b917 = { ee 65 [2] dc 47 [2] da 72 [2] f4 72 [2] cb 6e }

  condition:
    any of them
}