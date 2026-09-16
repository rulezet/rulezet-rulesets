rule TTP_XOR_WriteProcessMemory_b9cd {
  strings:
    $key_b9cd = { ee bf [2] dc 9d [2] da a8 [2] f4 a8 [2] cb b4 }

  condition:
    any of them
}