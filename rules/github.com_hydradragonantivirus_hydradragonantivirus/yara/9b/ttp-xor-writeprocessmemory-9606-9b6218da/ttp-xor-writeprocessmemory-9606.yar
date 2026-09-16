rule TTP_XOR_WriteProcessMemory_9606 {
  strings:
    $key_9606 = { c1 74 [2] f3 56 [2] f5 63 [2] db 63 [2] e4 7f }

  condition:
    any of them
}