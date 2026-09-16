rule TTP_XOR_WriteProcessMemory_9da7 {
  strings:
    $key_9da7 = { ca d5 [2] f8 f7 [2] fe c2 [2] d0 c2 [2] ef de }

  condition:
    any of them
}