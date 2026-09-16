rule TTP_XOR_WriteProcessMemory_9662 {
  strings:
    $key_9662 = { c1 10 [2] f3 32 [2] f5 07 [2] db 07 [2] e4 1b }

  condition:
    any of them
}