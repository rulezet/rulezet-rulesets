rule TTP_XOR_WriteProcessMemory_b913 {
  strings:
    $key_b913 = { ee 61 [2] dc 43 [2] da 76 [2] f4 76 [2] cb 6a }

  condition:
    any of them
}