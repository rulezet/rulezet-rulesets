rule TTP_XOR_WriteProcessMemory_b901 {
  strings:
    $key_b901 = { ee 73 [2] dc 51 [2] da 64 [2] f4 64 [2] cb 78 }

  condition:
    any of them
}