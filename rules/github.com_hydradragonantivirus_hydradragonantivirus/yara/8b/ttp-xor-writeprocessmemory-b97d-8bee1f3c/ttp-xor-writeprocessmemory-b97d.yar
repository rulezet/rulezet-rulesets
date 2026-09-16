rule TTP_XOR_WriteProcessMemory_b97d {
  strings:
    $key_b97d = { ee 0f [2] dc 2d [2] da 18 [2] f4 18 [2] cb 04 }

  condition:
    any of them
}