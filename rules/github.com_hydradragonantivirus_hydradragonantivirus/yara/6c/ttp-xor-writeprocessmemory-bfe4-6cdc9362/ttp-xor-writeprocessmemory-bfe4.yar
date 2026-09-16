rule TTP_XOR_WriteProcessMemory_bfe4 {
  strings:
    $key_bfe4 = { e8 96 [2] da b4 [2] dc 81 [2] f2 81 [2] cd 9d }

  condition:
    any of them
}