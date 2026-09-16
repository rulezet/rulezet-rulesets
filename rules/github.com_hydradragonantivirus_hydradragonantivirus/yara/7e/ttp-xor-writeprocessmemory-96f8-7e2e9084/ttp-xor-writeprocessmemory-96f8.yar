rule TTP_XOR_WriteProcessMemory_96f8 {
  strings:
    $key_96f8 = { c1 8a [2] f3 a8 [2] f5 9d [2] db 9d [2] e4 81 }

  condition:
    any of them
}