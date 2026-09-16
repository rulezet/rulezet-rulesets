rule TTP_XOR_WriteProcessMemory_9013 {
  strings:
    $key_9013 = { c7 61 [2] f5 43 [2] f3 76 [2] dd 76 [2] e2 6a }

  condition:
    any of them
}