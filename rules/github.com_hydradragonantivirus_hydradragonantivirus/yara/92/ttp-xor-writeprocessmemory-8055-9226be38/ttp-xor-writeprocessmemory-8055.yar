rule TTP_XOR_WriteProcessMemory_8055 {
  strings:
    $key_8055 = { d7 27 [2] e5 05 [2] e3 30 [2] cd 30 [2] f2 2c }

  condition:
    any of them
}