rule TTP_XOR_WriteProcessMemory_bf0c {
  strings:
    $key_bf0c = { e8 7e [2] da 5c [2] dc 69 [2] f2 69 [2] cd 75 }

  condition:
    any of them
}