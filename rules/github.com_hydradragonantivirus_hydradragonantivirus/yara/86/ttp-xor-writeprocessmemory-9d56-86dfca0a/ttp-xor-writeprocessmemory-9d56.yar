rule TTP_XOR_WriteProcessMemory_9d56 {
  strings:
    $key_9d56 = { ca 24 [2] f8 06 [2] fe 33 [2] d0 33 [2] ef 2f }

  condition:
    any of them
}