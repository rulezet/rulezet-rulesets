rule TTP_XOR_WriteProcessMemory_9ba1 {
  strings:
    $key_9ba1 = { cc d3 [2] fe f1 [2] f8 c4 [2] d6 c4 [2] e9 d8 }

  condition:
    any of them
}