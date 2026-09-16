rule TTP_XOR_WriteProcessMemory_b945 {
  strings:
    $key_b945 = { ee 37 [2] dc 15 [2] da 20 [2] f4 20 [2] cb 3c }

  condition:
    any of them
}