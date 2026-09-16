rule TTP_XOR_WriteProcessMemory_bf80 {
  strings:
    $key_bf80 = { e8 f2 [2] da d0 [2] dc e5 [2] f2 e5 [2] cd f9 }

  condition:
    any of them
}