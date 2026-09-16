rule TTP_XOR_WriteProcessMemory_b927 {
  strings:
    $key_b927 = { ee 55 [2] dc 77 [2] da 42 [2] f4 42 [2] cb 5e }

  condition:
    any of them
}