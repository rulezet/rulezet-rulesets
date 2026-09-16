rule TTP_XOR_WriteProcessMemory_b9d1 {
  strings:
    $key_b9d1 = { ee a3 [2] dc 81 [2] da b4 [2] f4 b4 [2] cb a8 }

  condition:
    any of them
}