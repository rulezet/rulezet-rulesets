rule TTP_XOR_WriteProcessMemory_bf5b {
  strings:
    $key_bf5b = { e8 29 [2] da 0b [2] dc 3e [2] f2 3e [2] cd 22 }

  condition:
    any of them
}