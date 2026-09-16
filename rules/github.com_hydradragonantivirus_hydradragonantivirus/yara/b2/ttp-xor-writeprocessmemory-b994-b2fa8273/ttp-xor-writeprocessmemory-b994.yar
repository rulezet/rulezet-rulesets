rule TTP_XOR_WriteProcessMemory_b994 {
  strings:
    $key_b994 = { ee e6 [2] dc c4 [2] da f1 [2] f4 f1 [2] cb ed }

  condition:
    any of them
}