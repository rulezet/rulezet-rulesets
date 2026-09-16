rule TTP_XOR_WriteProcessMemory_bf52 {
  strings:
    $key_bf52 = { e8 20 [2] da 02 [2] dc 37 [2] f2 37 [2] cd 2b }

  condition:
    any of them
}