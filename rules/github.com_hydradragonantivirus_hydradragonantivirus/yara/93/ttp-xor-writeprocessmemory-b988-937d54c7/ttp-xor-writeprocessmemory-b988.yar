rule TTP_XOR_WriteProcessMemory_b988 {
  strings:
    $key_b988 = { ee fa [2] dc d8 [2] da ed [2] f4 ed [2] cb f1 }

  condition:
    any of them
}