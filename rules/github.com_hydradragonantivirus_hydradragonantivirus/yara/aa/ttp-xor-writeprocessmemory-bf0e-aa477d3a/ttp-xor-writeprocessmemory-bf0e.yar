rule TTP_XOR_WriteProcessMemory_bf0e {
  strings:
    $key_bf0e = { e8 7c [2] da 5e [2] dc 6b [2] f2 6b [2] cd 77 }

  condition:
    any of them
}