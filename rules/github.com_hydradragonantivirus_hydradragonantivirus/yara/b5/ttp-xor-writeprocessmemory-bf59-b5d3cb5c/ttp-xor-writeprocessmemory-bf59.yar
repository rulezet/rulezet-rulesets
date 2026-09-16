rule TTP_XOR_WriteProcessMemory_bf59 {
  strings:
    $key_bf59 = { e8 2b [2] da 09 [2] dc 3c [2] f2 3c [2] cd 20 }

  condition:
    any of them
}