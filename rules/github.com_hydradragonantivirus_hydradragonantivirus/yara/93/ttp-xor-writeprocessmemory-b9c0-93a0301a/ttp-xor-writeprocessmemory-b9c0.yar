rule TTP_XOR_WriteProcessMemory_b9c0 {
  strings:
    $key_b9c0 = { ee b2 [2] dc 90 [2] da a5 [2] f4 a5 [2] cb b9 }

  condition:
    any of them
}