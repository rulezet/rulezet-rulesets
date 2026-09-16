rule TTP_XOR_WriteProcessMemory_9d63 {
  strings:
    $key_9d63 = { ca 11 [2] f8 33 [2] fe 06 [2] d0 06 [2] ef 1a }

  condition:
    any of them
}