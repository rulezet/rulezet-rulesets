rule TTP_XOR_WriteProcessMemory_8047 {
  strings:
    $key_8047 = { d7 35 [2] e5 17 [2] e3 22 [2] cd 22 [2] f2 3e }

  condition:
    any of them
}