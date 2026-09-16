rule TTP_XOR_WriteProcessMemory_8023 {
  strings:
    $key_8023 = { d7 51 [2] e5 73 [2] e3 46 [2] cd 46 [2] f2 5a }

  condition:
    any of them
}