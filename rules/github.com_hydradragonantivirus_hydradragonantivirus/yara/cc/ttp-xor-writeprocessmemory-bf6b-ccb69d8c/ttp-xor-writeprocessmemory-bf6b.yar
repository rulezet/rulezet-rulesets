rule TTP_XOR_WriteProcessMemory_bf6b {
  strings:
    $key_bf6b = { e8 19 [2] da 3b [2] dc 0e [2] f2 0e [2] cd 12 }

  condition:
    any of them
}