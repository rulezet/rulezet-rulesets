rule TTP_XOR_WriteProcessMemory_bfdf {
  strings:
    $key_bfdf = { e8 ad [2] da 8f [2] dc ba [2] f2 ba [2] cd a6 }

  condition:
    any of them
}