rule TTP_XOR_WriteProcessMemory_bf6e {
  strings:
    $key_bf6e = { e8 1c [2] da 3e [2] dc 0b [2] f2 0b [2] cd 17 }

  condition:
    any of them
}