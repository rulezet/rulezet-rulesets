rule TTP_XOR_WriteProcessMemory_bf8a {
  strings:
    $key_bf8a = { e8 f8 [2] da da [2] dc ef [2] f2 ef [2] cd f3 }

  condition:
    any of them
}