rule TTP_XOR_WriteProcessMemory_bf4c {
  strings:
    $key_bf4c = { e8 3e [2] da 1c [2] dc 29 [2] f2 29 [2] cd 35 }

  condition:
    any of them
}