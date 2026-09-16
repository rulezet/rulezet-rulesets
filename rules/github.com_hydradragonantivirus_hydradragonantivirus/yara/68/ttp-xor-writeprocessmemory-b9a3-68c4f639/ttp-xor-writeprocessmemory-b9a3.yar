rule TTP_XOR_WriteProcessMemory_b9a3 {
  strings:
    $key_b9a3 = { ee d1 [2] dc f3 [2] da c6 [2] f4 c6 [2] cb da }

  condition:
    any of them
}