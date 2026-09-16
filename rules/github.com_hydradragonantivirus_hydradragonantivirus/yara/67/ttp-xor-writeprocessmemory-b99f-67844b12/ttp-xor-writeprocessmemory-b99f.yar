rule TTP_XOR_WriteProcessMemory_b99f {
  strings:
    $key_b99f = { ee ed [2] dc cf [2] da fa [2] f4 fa [2] cb e6 }

  condition:
    any of them
}