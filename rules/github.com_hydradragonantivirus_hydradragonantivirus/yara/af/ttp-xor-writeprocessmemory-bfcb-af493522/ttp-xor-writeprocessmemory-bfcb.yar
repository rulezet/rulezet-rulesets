rule TTP_XOR_WriteProcessMemory_bfcb {
  strings:
    $key_bfcb = { e8 b9 [2] da 9b [2] dc ae [2] f2 ae [2] cd b2 }

  condition:
    any of them
}