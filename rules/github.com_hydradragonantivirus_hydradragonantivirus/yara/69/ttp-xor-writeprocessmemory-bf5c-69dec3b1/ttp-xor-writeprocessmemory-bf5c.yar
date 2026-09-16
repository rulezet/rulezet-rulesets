rule TTP_XOR_WriteProcessMemory_bf5c {
  strings:
    $key_bf5c = { e8 2e [2] da 0c [2] dc 39 [2] f2 39 [2] cd 25 }

  condition:
    any of them
}