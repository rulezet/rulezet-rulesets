rule TTP_XOR_WriteProcessMemory_a897 {
  strings:
    $key_a897 = { ff e5 [2] cd c7 [2] cb f2 [2] e5 f2 [2] da ee }

  condition:
    any of them
}