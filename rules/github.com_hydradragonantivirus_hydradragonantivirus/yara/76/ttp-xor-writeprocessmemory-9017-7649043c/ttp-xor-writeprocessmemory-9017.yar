rule TTP_XOR_WriteProcessMemory_9017 {
  strings:
    $key_9017 = { c7 65 [2] f5 47 [2] f3 72 [2] dd 72 [2] e2 6e }

  condition:
    any of them
}