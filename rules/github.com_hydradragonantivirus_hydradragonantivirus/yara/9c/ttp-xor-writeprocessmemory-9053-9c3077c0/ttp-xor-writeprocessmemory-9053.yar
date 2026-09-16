rule TTP_XOR_WriteProcessMemory_9053 {
  strings:
    $key_9053 = { c7 21 [2] f5 03 [2] f3 36 [2] dd 36 [2] e2 2a }

  condition:
    any of them
}