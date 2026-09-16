rule TTP_XOR_WriteProcessMemory_b904 {
  strings:
    $key_b904 = { ee 76 [2] dc 54 [2] da 61 [2] f4 61 [2] cb 7d }

  condition:
    any of them
}