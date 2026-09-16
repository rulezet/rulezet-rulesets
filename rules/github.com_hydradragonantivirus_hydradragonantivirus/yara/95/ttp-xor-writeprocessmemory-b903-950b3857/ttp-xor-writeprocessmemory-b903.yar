rule TTP_XOR_WriteProcessMemory_b903 {
  strings:
    $key_b903 = { ee 71 [2] dc 53 [2] da 66 [2] f4 66 [2] cb 7a }

  condition:
    any of them
}