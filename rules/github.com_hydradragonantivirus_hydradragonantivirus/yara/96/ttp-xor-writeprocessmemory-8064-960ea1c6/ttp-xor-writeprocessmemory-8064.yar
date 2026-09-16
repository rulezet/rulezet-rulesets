rule TTP_XOR_WriteProcessMemory_8064 {
  strings:
    $key_8064 = { d7 16 [2] e5 34 [2] e3 01 [2] cd 01 [2] f2 1d }

  condition:
    any of them
}