rule TTP_XOR_WriteProcessMemory_bf37 {
  strings:
    $key_bf37 = { e8 45 [2] da 67 [2] dc 52 [2] f2 52 [2] cd 4e }

  condition:
    any of them
}