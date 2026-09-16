rule TTP_XOR_WriteProcessMemory_9077 {
  strings:
    $key_9077 = { c7 05 [2] f5 27 [2] f3 12 [2] dd 12 [2] e2 0e }

  condition:
    any of them
}