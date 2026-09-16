rule TTP_XOR_WriteProcessMemory_b98c {
  strings:
    $key_b98c = { ee fe [2] dc dc [2] da e9 [2] f4 e9 [2] cb f5 }

  condition:
    any of them
}