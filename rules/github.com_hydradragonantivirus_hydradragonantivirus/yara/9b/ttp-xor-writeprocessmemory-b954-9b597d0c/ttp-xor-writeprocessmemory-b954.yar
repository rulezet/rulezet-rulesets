rule TTP_XOR_WriteProcessMemory_b954 {
  strings:
    $key_b954 = { ee 26 [2] dc 04 [2] da 31 [2] f4 31 [2] cb 2d }

  condition:
    any of them
}