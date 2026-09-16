rule TTP_XOR_WriteProcessMemory_b905 {
  strings:
    $key_b905 = { ee 77 [2] dc 55 [2] da 60 [2] f4 60 [2] cb 7c }

  condition:
    any of them
}