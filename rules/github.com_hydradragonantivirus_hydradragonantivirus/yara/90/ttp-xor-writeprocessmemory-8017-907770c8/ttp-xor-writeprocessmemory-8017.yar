rule TTP_XOR_WriteProcessMemory_8017 {
  strings:
    $key_8017 = { d7 65 [2] e5 47 [2] e3 72 [2] cd 72 [2] f2 6e }

  condition:
    any of them
}