rule TTP_XOR_WriteProcessMemory_9050 {
  strings:
    $key_9050 = { c7 22 [2] f5 00 [2] f3 35 [2] dd 35 [2] e2 29 }

  condition:
    any of them
}