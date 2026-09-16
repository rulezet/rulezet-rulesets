rule TTP_XOR_WriteProcessMemory_9d42 {
  strings:
    $key_9d42 = { ca 30 [2] f8 12 [2] fe 27 [2] d0 27 [2] ef 3b }

  condition:
    any of them
}