rule TTP_XOR_WriteProcessMemory_bf7c {
  strings:
    $key_bf7c = { e8 0e [2] da 2c [2] dc 19 [2] f2 19 [2] cd 05 }

  condition:
    any of them
}