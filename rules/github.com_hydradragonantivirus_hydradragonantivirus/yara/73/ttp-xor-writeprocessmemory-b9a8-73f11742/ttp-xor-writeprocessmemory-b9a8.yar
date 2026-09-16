rule TTP_XOR_WriteProcessMemory_b9a8 {
  strings:
    $key_b9a8 = { ee da [2] dc f8 [2] da cd [2] f4 cd [2] cb d1 }

  condition:
    any of them
}