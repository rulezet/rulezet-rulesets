rule TTP_XOR_WriteProcessMemory_bf0b {
  strings:
    $key_bf0b = { e8 79 [2] da 5b [2] dc 6e [2] f2 6e [2] cd 72 }

  condition:
    any of them
}