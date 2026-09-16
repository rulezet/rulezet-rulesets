rule TTP_XOR_WriteProcessMemory_9600 {
  strings:
    $key_9600 = { c1 72 [2] f3 50 [2] f5 65 [2] db 65 [2] e4 79 }

  condition:
    any of them
}