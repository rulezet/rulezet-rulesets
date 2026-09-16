rule TTP_XOR_WriteProcessMemory_9d00 {
  strings:
    $key_9d00 = { ca 72 [2] f8 50 [2] fe 65 [2] d0 65 [2] ef 79 }

  condition:
    any of them
}