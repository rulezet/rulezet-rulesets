rule TTP_XOR_WriteProcessMemory_96f7 {
  strings:
    $key_96f7 = { c1 85 [2] f3 a7 [2] f5 92 [2] db 92 [2] e4 8e }

  condition:
    any of them
}