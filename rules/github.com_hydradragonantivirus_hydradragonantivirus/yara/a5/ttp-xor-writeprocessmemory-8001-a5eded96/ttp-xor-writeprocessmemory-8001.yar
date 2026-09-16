rule TTP_XOR_WriteProcessMemory_8001 {
  strings:
    $key_8001 = { d7 73 [2] e5 51 [2] e3 64 [2] cd 64 [2] f2 78 }

  condition:
    any of them
}