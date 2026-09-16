rule TTP_XOR_WriteProcessMemory_9037 {
  strings:
    $key_9037 = { c7 45 [2] f5 67 [2] f3 52 [2] dd 52 [2] e2 4e }

  condition:
    any of them
}