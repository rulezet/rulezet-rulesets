rule TTP_XOR_WriteProcessMemory_96f9 {
  strings:
    $key_96f9 = { c1 8b [2] f3 a9 [2] f5 9c [2] db 9c [2] e4 80 }

  condition:
    any of them
}