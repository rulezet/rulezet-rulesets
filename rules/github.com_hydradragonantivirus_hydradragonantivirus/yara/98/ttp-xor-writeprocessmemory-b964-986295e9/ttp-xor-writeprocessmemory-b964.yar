rule TTP_XOR_WriteProcessMemory_b964 {
  strings:
    $key_b964 = { ee 16 [2] dc 34 [2] da 01 [2] f4 01 [2] cb 1d }

  condition:
    any of them
}