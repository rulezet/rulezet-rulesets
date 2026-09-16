rule TTP_XOR_WriteProcessMemory_bf25 {
  strings:
    $key_bf25 = { e8 57 [2] da 75 [2] dc 40 [2] f2 40 [2] cd 5c }

  condition:
    any of them
}