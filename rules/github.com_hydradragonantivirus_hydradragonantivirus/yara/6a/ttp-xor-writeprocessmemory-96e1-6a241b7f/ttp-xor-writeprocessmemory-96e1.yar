rule TTP_XOR_WriteProcessMemory_96e1 {
  strings:
    $key_96e1 = { c1 93 [2] f3 b1 [2] f5 84 [2] db 84 [2] e4 98 }

  condition:
    any of them
}