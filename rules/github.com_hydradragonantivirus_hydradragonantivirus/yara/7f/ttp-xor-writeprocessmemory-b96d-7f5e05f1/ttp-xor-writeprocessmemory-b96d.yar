rule TTP_XOR_WriteProcessMemory_b96d {
  strings:
    $key_b96d = { ee 1f [2] dc 3d [2] da 08 [2] f4 08 [2] cb 14 }

  condition:
    any of them
}