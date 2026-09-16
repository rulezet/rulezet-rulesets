rule TTP_XOR_WriteProcessMemory_bf05 {
  strings:
    $key_bf05 = { e8 77 [2] da 55 [2] dc 60 [2] f2 60 [2] cd 7c }

  condition:
    any of them
}