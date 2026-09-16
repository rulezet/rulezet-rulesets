rule TTP_XOR_WriteProcessMemory_bf3c {
  strings:
    $key_bf3c = { e8 4e [2] da 6c [2] dc 59 [2] f2 59 [2] cd 45 }

  condition:
    any of them
}