rule TTP_XOR_WriteProcessMemory_9617 {
  strings:
    $key_9617 = { c1 65 [2] f3 47 [2] f5 72 [2] db 72 [2] e4 6e }

  condition:
    any of them
}