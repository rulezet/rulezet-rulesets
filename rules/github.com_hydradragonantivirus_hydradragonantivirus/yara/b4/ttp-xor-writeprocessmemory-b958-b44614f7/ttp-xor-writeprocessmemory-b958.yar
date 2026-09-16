rule TTP_XOR_WriteProcessMemory_b958 {
  strings:
    $key_b958 = { ee 2a [2] dc 08 [2] da 3d [2] f4 3d [2] cb 21 }

  condition:
    any of them
}