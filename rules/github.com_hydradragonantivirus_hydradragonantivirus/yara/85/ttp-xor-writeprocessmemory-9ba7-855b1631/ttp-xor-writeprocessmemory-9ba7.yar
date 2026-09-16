rule TTP_XOR_WriteProcessMemory_9ba7 {
  strings:
    $key_9ba7 = { cc d5 [2] fe f7 [2] f8 c2 [2] d6 c2 [2] e9 de }

  condition:
    any of them
}