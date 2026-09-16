rule TTP_XOR_WriteProcessMemory_bf2c {
  strings:
    $key_bf2c = { e8 5e [2] da 7c [2] dc 49 [2] f2 49 [2] cd 55 }

  condition:
    any of them
}