rule TTP_XOR_WriteProcessMemory_8020 {
  strings:
    $key_8020 = { d7 52 [2] e5 70 [2] e3 45 [2] cd 45 [2] f2 59 }

  condition:
    any of them
}