rule TTP_XOR_WriteProcessMemory_9da2 {
  strings:
    $key_9da2 = { ca d0 [2] f8 f2 [2] fe c7 [2] d0 c7 [2] ef db }

  condition:
    any of them
}