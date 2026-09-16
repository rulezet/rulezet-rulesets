rule TTP_XOR_WriteProcessMemory_b9aa {
  strings:
    $key_b9aa = { ee d8 [2] dc fa [2] da cf [2] f4 cf [2] cb d3 }

  condition:
    any of them
}