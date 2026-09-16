rule TTP_XOR_WriteProcessMemory_b98b {
  strings:
    $key_b98b = { ee f9 [2] dc db [2] da ee [2] f4 ee [2] cb f2 }

  condition:
    any of them
}