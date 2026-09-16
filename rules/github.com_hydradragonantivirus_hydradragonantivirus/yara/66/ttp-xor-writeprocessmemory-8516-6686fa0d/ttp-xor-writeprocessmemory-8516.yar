rule TTP_XOR_WriteProcessMemory_8516 {
  strings:
    $key_8516 = { d2 64 [2] e0 46 [2] e6 73 [2] c8 73 [2] f7 6f }

  condition:
    any of them
}