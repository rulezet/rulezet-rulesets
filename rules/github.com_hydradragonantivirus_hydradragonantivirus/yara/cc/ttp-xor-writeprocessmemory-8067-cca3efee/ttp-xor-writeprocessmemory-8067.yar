rule TTP_XOR_WriteProcessMemory_8067 {
  strings:
    $key_8067 = { d7 15 [2] e5 37 [2] e3 02 [2] cd 02 [2] f2 1e }

  condition:
    any of them
}