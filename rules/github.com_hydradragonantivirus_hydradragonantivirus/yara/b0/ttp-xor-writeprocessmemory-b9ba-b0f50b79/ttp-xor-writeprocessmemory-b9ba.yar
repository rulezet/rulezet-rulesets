rule TTP_XOR_WriteProcessMemory_b9ba {
  strings:
    $key_b9ba = { ee c8 [2] dc ea [2] da df [2] f4 df [2] cb c3 }

  condition:
    any of them
}