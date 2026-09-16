rule TTP_XOR_WriteProcessMemory_bfb8 {
  strings:
    $key_bfb8 = { e8 ca [2] da e8 [2] dc dd [2] f2 dd [2] cd c1 }

  condition:
    any of them
}