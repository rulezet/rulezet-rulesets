rule TTP_XOR_WriteProcessMemory_bf12 {
  strings:
    $key_bf12 = { e8 60 [2] da 42 [2] dc 77 [2] f2 77 [2] cd 6b }

  condition:
    any of them
}