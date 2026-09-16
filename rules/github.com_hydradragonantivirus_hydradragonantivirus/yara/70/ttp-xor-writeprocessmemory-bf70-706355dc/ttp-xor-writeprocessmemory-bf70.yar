rule TTP_XOR_WriteProcessMemory_bf70 {
  strings:
    $key_bf70 = { e8 02 [2] da 20 [2] dc 15 [2] f2 15 [2] cd 09 }

  condition:
    any of them
}