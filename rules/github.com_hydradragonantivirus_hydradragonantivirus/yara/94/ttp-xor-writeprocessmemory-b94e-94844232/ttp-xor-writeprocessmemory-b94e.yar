rule TTP_XOR_WriteProcessMemory_b94e {
  strings:
    $key_b94e = { ee 3c [2] dc 1e [2] da 2b [2] f4 2b [2] cb 37 }

  condition:
    any of them
}