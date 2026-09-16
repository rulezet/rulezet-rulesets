rule TTP_XOR_WriteProcessMemory_bff4 {
  strings:
    $key_bff4 = { e8 86 [2] da a4 [2] dc 91 [2] f2 91 [2] cd 8d }

  condition:
    any of them
}