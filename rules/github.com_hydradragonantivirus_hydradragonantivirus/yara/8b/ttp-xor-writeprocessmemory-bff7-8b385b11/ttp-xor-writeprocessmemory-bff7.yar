rule TTP_XOR_WriteProcessMemory_bff7 {
  strings:
    $key_bff7 = { e8 85 [2] da a7 [2] dc 92 [2] f2 92 [2] cd 8e }

  condition:
    any of them
}