rule TTP_XOR_WriteProcessMemory_bf77 {
  strings:
    $key_bf77 = { e8 05 [2] da 27 [2] dc 12 [2] f2 12 [2] cd 0e }

  condition:
    any of them
}