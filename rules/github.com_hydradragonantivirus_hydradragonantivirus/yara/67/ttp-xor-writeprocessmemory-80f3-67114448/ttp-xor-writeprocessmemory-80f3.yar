rule TTP_XOR_WriteProcessMemory_80f3 {
  strings:
    $key_80f3 = { d7 81 [2] e5 a3 [2] e3 96 [2] cd 96 [2] f2 8a }

  condition:
    any of them
}