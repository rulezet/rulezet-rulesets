rule TTP_XOR_WriteProcessMemory_9da0 {
  strings:
    $key_9da0 = { ca d2 [2] f8 f0 [2] fe c5 [2] d0 c5 [2] ef d9 }

  condition:
    any of them
}