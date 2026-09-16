rule TTP_XOR_WriteProcessMemory_9ba5 {
  strings:
    $key_9ba5 = { cc d7 [2] fe f5 [2] f8 c0 [2] d6 c0 [2] e9 dc }

  condition:
    any of them
}