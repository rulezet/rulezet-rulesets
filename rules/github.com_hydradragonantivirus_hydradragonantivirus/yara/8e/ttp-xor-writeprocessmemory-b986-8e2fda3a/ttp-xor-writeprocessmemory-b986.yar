rule TTP_XOR_WriteProcessMemory_b986 {
  strings:
    $key_b986 = { ee f4 [2] dc d6 [2] da e3 [2] f4 e3 [2] cb ff }

  condition:
    any of them
}