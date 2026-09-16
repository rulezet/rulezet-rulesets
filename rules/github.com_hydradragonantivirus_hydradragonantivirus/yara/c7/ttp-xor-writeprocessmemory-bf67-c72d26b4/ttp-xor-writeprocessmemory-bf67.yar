rule TTP_XOR_WriteProcessMemory_bf67 {
  strings:
    $key_bf67 = { e8 15 [2] da 37 [2] dc 02 [2] f2 02 [2] cd 1e }

  condition:
    any of them
}