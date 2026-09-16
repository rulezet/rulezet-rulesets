rule TTP_XOR_WriteProcessMemory_9ba3 {
  strings:
    $key_9ba3 = { cc d1 [2] fe f3 [2] f8 c6 [2] d6 c6 [2] e9 da }

  condition:
    any of them
}