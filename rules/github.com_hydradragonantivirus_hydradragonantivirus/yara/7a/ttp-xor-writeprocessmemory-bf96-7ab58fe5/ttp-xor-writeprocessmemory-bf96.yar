rule TTP_XOR_WriteProcessMemory_bf96 {
  strings:
    $key_bf96 = { e8 e4 [2] da c6 [2] dc f3 [2] f2 f3 [2] cd ef }

  condition:
    any of them
}