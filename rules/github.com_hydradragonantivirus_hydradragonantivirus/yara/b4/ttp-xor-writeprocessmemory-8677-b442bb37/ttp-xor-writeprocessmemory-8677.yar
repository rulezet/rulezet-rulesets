rule TTP_XOR_WriteProcessMemory_8677 {
  strings:
    $key_8677 = { d1 05 [2] e3 27 [2] e5 12 [2] cb 12 [2] f4 0e }

  condition:
    any of them
}