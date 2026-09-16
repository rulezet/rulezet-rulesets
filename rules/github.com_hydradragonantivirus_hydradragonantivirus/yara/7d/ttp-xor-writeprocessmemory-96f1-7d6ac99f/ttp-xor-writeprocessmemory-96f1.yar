rule TTP_XOR_WriteProcessMemory_96f1 {
  strings:
    $key_96f1 = { c1 83 [2] f3 a1 [2] f5 94 [2] db 94 [2] e4 88 }

  condition:
    any of them
}