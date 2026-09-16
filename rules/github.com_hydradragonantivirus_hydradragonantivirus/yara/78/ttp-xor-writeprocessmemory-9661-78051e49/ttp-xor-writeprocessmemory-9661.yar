rule TTP_XOR_WriteProcessMemory_9661 {
  strings:
    $key_9661 = { c1 13 [2] f3 31 [2] f5 04 [2] db 04 [2] e4 18 }

  condition:
    any of them
}