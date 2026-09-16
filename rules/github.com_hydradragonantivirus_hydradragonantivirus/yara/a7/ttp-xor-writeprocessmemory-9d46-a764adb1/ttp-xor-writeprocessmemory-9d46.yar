rule TTP_XOR_WriteProcessMemory_9d46 {
  strings:
    $key_9d46 = { ca 34 [2] f8 16 [2] fe 23 [2] d0 23 [2] ef 3f }

  condition:
    any of them
}