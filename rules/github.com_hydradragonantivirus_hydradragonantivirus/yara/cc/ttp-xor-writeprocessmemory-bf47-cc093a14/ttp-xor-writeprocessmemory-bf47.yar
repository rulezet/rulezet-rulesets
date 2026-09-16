rule TTP_XOR_WriteProcessMemory_bf47 {
  strings:
    $key_bf47 = { e8 35 [2] da 17 [2] dc 22 [2] f2 22 [2] cd 3e }

  condition:
    any of them
}