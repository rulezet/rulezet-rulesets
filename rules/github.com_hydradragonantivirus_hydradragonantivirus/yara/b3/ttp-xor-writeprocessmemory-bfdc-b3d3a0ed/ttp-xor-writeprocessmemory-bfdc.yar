rule TTP_XOR_WriteProcessMemory_bfdc {
  strings:
    $key_bfdc = { e8 ae [2] da 8c [2] dc b9 [2] f2 b9 [2] cd a5 }

  condition:
    any of them
}