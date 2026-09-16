rule TTP_XOR_WriteProcessMemory_bf3b {
  strings:
    $key_bf3b = { e8 49 [2] da 6b [2] dc 5e [2] f2 5e [2] cd 42 }

  condition:
    any of them
}