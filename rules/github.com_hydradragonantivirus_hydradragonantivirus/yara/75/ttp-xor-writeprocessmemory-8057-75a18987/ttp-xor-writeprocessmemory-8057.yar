rule TTP_XOR_WriteProcessMemory_8057 {
  strings:
    $key_8057 = { d7 25 [2] e5 07 [2] e3 32 [2] cd 32 [2] f2 2e }

  condition:
    any of them
}