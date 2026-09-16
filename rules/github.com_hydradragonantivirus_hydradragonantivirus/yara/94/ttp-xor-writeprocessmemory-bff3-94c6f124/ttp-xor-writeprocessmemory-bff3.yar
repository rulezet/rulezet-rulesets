rule TTP_XOR_WriteProcessMemory_bff3 {
  strings:
    $key_bff3 = { e8 81 [2] da a3 [2] dc 96 [2] f2 96 [2] cd 8a }

  condition:
    any of them
}