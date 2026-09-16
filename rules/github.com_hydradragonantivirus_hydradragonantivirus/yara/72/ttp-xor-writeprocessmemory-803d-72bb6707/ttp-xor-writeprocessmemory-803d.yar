rule TTP_XOR_WriteProcessMemory_803d {
  strings:
    $key_803d = { d7 4f [2] e5 6d [2] e3 58 [2] cd 58 [2] f2 44 }

  condition:
    any of them
}