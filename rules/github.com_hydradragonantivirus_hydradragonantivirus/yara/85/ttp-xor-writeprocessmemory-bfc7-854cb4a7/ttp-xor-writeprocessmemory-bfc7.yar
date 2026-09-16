rule TTP_XOR_WriteProcessMemory_bfc7 {
  strings:
    $key_bfc7 = { e8 b5 [2] da 97 [2] dc a2 [2] f2 a2 [2] cd be }

  condition:
    any of them
}