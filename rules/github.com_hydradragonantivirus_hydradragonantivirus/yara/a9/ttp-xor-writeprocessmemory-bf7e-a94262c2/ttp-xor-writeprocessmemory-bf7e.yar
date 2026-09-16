rule TTP_XOR_WriteProcessMemory_bf7e {
  strings:
    $key_bf7e = { e8 0c [2] da 2e [2] dc 1b [2] f2 1b [2] cd 07 }

  condition:
    any of them
}