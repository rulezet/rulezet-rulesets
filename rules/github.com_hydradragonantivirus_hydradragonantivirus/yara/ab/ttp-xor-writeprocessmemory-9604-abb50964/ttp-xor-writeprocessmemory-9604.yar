rule TTP_XOR_WriteProcessMemory_9604 {
  strings:
    $key_9604 = { c1 76 [2] f3 54 [2] f5 61 [2] db 61 [2] e4 7d }

  condition:
    any of them
}