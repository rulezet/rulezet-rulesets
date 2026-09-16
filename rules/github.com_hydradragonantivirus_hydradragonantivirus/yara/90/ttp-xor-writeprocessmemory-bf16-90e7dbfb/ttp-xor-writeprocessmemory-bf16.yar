rule TTP_XOR_WriteProcessMemory_bf16 {
  strings:
    $key_bf16 = { e8 64 [2] da 46 [2] dc 73 [2] f2 73 [2] cd 6f }

  condition:
    any of them
}