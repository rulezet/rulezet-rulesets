rule TTP_XOR_WriteProcessMemory_9d26 {
  strings:
    $key_9d26 = { ca 54 [2] f8 76 [2] fe 43 [2] d0 43 [2] ef 5f }

  condition:
    any of them
}