rule TTP_XOR_WriteProcessMemory_b981 {
  strings:
    $key_b981 = { ee f3 [2] dc d1 [2] da e4 [2] f4 e4 [2] cb f8 }

  condition:
    any of them
}