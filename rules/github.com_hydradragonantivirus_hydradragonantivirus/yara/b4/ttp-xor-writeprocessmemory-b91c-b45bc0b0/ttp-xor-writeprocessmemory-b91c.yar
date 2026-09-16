rule TTP_XOR_WriteProcessMemory_b91c {
  strings:
    $key_b91c = { ee 6e [2] dc 4c [2] da 79 [2] f4 79 [2] cb 65 }

  condition:
    any of them
}