rule TTP_XOR_WriteProcessMemory_bf54 {
  strings:
    $key_bf54 = { e8 26 [2] da 04 [2] dc 31 [2] f2 31 [2] cd 2d }

  condition:
    any of them
}