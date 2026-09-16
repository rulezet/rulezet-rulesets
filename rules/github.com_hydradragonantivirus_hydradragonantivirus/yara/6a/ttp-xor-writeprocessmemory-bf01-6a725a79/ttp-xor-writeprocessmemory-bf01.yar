rule TTP_XOR_WriteProcessMemory_bf01 {
  strings:
    $key_bf01 = { e8 73 [2] da 51 [2] dc 64 [2] f2 64 [2] cd 78 }

  condition:
    any of them
}