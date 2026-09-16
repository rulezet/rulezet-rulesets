rule TTP_XOR_WriteProcessMemory_9016 {
  strings:
    $key_9016 = { c7 64 [2] f5 46 [2] f3 73 [2] dd 73 [2] e2 6f }

  condition:
    any of them
}