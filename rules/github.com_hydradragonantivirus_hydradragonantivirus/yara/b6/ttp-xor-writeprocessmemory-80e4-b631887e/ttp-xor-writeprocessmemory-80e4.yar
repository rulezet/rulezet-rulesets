rule TTP_XOR_WriteProcessMemory_80e4 {
  strings:
    $key_80e4 = { d7 96 [2] e5 b4 [2] e3 81 [2] cd 81 [2] f2 9d }

  condition:
    any of them
}