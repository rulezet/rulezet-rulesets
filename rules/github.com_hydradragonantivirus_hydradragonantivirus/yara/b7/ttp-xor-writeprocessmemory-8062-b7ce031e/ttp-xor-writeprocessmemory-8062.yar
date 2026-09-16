rule TTP_XOR_WriteProcessMemory_8062 {
  strings:
    $key_8062 = { d7 10 [2] e5 32 [2] e3 07 [2] cd 07 [2] f2 1b }

  condition:
    any of them
}