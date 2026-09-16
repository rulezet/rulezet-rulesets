rule TTP_XOR_WriteProcessMemory_b96e {
  strings:
    $key_b96e = { ee 1c [2] dc 3e [2] da 0b [2] f4 0b [2] cb 17 }

  condition:
    any of them
}