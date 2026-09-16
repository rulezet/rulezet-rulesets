rule TTP_XOR_WriteProcessMemory_96e4 {
  strings:
    $key_96e4 = { c1 96 [2] f3 b4 [2] f5 81 [2] db 81 [2] e4 9d }

  condition:
    any of them
}