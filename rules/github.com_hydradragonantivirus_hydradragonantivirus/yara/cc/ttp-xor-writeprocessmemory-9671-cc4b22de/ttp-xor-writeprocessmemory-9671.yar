rule TTP_XOR_WriteProcessMemory_9671 {
  strings:
    $key_9671 = { c1 03 [2] f3 21 [2] f5 14 [2] db 14 [2] e4 08 }

  condition:
    any of them
}