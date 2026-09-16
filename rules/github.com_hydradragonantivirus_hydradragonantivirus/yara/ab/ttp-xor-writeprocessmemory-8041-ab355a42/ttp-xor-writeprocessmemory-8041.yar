rule TTP_XOR_WriteProcessMemory_8041 {
  strings:
    $key_8041 = { d7 33 [2] e5 11 [2] e3 24 [2] cd 24 [2] f2 38 }

  condition:
    any of them
}