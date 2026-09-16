rule TTP_XOR_WriteProcessMemory_bf9c {
  strings:
    $key_bf9c = { e8 ee [2] da cc [2] dc f9 [2] f2 f9 [2] cd e5 }

  condition:
    any of them
}