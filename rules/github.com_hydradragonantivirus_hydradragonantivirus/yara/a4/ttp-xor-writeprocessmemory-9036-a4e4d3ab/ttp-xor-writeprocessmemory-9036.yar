rule TTP_XOR_WriteProcessMemory_9036 {
  strings:
    $key_9036 = { c7 44 [2] f5 66 [2] f3 53 [2] dd 53 [2] e2 4f }

  condition:
    any of them
}