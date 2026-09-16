rule TTP_XOR_WriteProcessMemory_bf3e {
  strings:
    $key_bf3e = { e8 4c [2] da 6e [2] dc 5b [2] f2 5b [2] cd 47 }

  condition:
    any of them
}