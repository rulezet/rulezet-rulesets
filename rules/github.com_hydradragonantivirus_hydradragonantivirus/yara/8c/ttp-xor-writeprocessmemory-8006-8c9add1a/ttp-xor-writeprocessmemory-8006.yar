rule TTP_XOR_WriteProcessMemory_8006 {
  strings:
    $key_8006 = { d7 74 [2] e5 56 [2] e3 63 [2] cd 63 [2] f2 7f }

  condition:
    any of them
}