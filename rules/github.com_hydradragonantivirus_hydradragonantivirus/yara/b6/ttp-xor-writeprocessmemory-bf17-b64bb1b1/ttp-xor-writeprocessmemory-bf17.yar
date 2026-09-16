rule TTP_XOR_WriteProcessMemory_bf17 {
  strings:
    $key_bf17 = { e8 65 [2] da 47 [2] dc 72 [2] f2 72 [2] cd 6e }

  condition:
    any of them
}