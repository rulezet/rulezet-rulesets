rule TTP_XOR_WriteProcessMemory_96e6 {
  strings:
    $key_96e6 = { c1 94 [2] f3 b6 [2] f5 83 [2] db 83 [2] e4 9f }

  condition:
    any of them
}