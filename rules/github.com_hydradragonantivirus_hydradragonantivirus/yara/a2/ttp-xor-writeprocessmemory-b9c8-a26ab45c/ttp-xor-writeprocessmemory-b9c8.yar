rule TTP_XOR_WriteProcessMemory_b9c8 {
  strings:
    $key_b9c8 = { ee ba [2] dc 98 [2] da ad [2] f4 ad [2] cb b1 }

  condition:
    any of them
}