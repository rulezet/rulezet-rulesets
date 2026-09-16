rule TTP_XOR_WriteProcessMemory_bf61 {
  strings:
    $key_bf61 = { e8 13 [2] da 31 [2] dc 04 [2] f2 04 [2] cd 18 }

  condition:
    any of them
}