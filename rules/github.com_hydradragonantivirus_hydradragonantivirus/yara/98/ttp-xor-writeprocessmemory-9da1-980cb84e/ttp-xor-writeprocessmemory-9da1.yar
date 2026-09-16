rule TTP_XOR_WriteProcessMemory_9da1 {
  strings:
    $key_9da1 = { ca d3 [2] f8 f1 [2] fe c4 [2] d0 c4 [2] ef d8 }

  condition:
    any of them
}