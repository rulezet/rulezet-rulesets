rule TTP_XOR_WriteProcessMemory_9026 {
  strings:
    $key_9026 = { c7 54 [2] f5 76 [2] f3 43 [2] dd 43 [2] e2 5f }

  condition:
    any of them
}