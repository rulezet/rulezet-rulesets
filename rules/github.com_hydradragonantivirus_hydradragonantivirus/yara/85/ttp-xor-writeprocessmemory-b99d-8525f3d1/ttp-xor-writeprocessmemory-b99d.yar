rule TTP_XOR_WriteProcessMemory_b99d {
  strings:
    $key_b99d = { ee ef [2] dc cd [2] da f8 [2] f4 f8 [2] cb e4 }

  condition:
    any of them
}