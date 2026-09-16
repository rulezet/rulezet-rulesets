rule TTP_XOR_WriteProcessMemory_b9da {
  strings:
    $key_b9da = { ee a8 [2] dc 8a [2] da bf [2] f4 bf [2] cb a3 }

  condition:
    any of them
}