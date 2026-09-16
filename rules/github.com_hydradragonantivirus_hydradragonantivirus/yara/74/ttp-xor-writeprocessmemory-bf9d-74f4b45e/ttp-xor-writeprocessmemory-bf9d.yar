rule TTP_XOR_WriteProcessMemory_bf9d {
  strings:
    $key_bf9d = { e8 ef [2] da cd [2] dc f8 [2] f2 f8 [2] cd e4 }

  condition:
    any of them
}