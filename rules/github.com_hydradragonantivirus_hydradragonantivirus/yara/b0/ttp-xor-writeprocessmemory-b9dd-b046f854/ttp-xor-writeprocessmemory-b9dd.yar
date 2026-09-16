rule TTP_XOR_WriteProcessMemory_b9dd {
  strings:
    $key_b9dd = { ee af [2] dc 8d [2] da b8 [2] f4 b8 [2] cb a4 }

  condition:
    any of them
}