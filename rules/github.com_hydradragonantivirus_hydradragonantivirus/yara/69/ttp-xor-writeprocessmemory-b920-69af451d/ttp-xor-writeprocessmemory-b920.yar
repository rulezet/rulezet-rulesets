rule TTP_XOR_WriteProcessMemory_b920 {
  strings:
    $key_b920 = { ee 52 [2] dc 70 [2] da 45 [2] f4 45 [2] cb 59 }

  condition:
    any of them
}