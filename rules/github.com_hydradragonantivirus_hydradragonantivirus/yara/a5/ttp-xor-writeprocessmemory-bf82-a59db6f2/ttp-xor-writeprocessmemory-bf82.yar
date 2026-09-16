rule TTP_XOR_WriteProcessMemory_bf82 {
  strings:
    $key_bf82 = { e8 f0 [2] da d2 [2] dc e7 [2] f2 e7 [2] cd fb }

  condition:
    any of them
}