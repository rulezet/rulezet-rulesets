rule TTP_XOR_WriteProcessMemory_8000 {
  strings:
    $key_8000 = { d7 72 [2] e5 50 [2] e3 65 [2] cd 65 [2] f2 79 }

  condition:
    any of them
}