rule TTP_XOR_WriteProcessMemory_bf2b {
  strings:
    $key_bf2b = { e8 59 [2] da 7b [2] dc 4e [2] f2 4e [2] cd 52 }

  condition:
    any of them
}