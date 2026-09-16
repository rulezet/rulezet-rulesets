rule TTP_XOR_WriteProcessMemory_b9a0 {
  strings:
    $key_b9a0 = { ee d2 [2] dc f0 [2] da c5 [2] f4 c5 [2] cb d9 }

  condition:
    any of them
}