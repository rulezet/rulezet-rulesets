rule TTP_XOR_WriteProcessMemory_8053 {
  strings:
    $key_8053 = { d7 21 [2] e5 03 [2] e3 36 [2] cd 36 [2] f2 2a }

  condition:
    any of them
}