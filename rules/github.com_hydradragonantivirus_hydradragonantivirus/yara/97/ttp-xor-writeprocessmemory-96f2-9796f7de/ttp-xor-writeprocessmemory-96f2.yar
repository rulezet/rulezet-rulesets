rule TTP_XOR_WriteProcessMemory_96f2 {
  strings:
    $key_96f2 = { c1 80 [2] f3 a2 [2] f5 97 [2] db 97 [2] e4 8b }

  condition:
    any of them
}