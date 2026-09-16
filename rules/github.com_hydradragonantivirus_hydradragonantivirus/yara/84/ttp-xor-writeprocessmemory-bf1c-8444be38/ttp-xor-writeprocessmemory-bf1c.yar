rule TTP_XOR_WriteProcessMemory_bf1c {
  strings:
    $key_bf1c = { e8 6e [2] da 4c [2] dc 79 [2] f2 79 [2] cd 65 }

  condition:
    any of them
}