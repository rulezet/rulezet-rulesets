rule TTP_XOR_WriteProcessMemory_b90e {
  strings:
    $key_b90e = { ee 7c [2] dc 5e [2] da 6b [2] f4 6b [2] cb 77 }

  condition:
    any of them
}