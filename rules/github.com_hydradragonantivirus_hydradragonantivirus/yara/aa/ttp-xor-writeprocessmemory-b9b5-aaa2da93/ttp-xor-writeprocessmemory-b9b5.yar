rule TTP_XOR_WriteProcessMemory_b9b5 {
  strings:
    $key_b9b5 = { ee c7 [2] dc e5 [2] da d0 [2] f4 d0 [2] cb cc }

  condition:
    any of them
}