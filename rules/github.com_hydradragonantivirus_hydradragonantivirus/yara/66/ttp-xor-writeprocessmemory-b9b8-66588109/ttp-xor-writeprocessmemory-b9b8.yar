rule TTP_XOR_WriteProcessMemory_b9b8 {
  strings:
    $key_b9b8 = { ee ca [2] dc e8 [2] da dd [2] f4 dd [2] cb c1 }

  condition:
    any of them
}