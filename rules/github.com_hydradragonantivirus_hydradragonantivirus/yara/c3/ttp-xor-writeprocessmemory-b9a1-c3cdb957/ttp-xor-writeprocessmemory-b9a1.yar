rule TTP_XOR_WriteProcessMemory_b9a1 {
  strings:
    $key_b9a1 = { ee d3 [2] dc f1 [2] da c4 [2] f4 c4 [2] cb d8 }

  condition:
    any of them
}