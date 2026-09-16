rule TTP_XOR_WriteProcessMemory_803b {
  strings:
    $key_803b = { d7 49 [2] e5 6b [2] e3 5e [2] cd 5e [2] f2 42 }

  condition:
    any of them
}