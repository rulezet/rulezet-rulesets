rule TTP_XOR_WriteProcessMemory_b933 {
  strings:
    $key_b933 = { ee 41 [2] dc 63 [2] da 56 [2] f4 56 [2] cb 4a }

  condition:
    any of them
}