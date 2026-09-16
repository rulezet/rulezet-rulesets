rule TTP_XOR_WriteProcessMemory_b911 {
  strings:
    $key_b911 = { ee 63 [2] dc 41 [2] da 74 [2] f4 74 [2] cb 68 }

  condition:
    any of them
}