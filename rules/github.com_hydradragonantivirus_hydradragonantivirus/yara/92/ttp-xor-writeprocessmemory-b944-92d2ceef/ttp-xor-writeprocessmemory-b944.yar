rule TTP_XOR_WriteProcessMemory_b944 {
  strings:
    $key_b944 = { ee 36 [2] dc 14 [2] da 21 [2] f4 21 [2] cb 3d }

  condition:
    any of them
}