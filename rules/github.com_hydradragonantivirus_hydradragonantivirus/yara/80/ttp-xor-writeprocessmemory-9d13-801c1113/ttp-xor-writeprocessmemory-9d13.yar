rule TTP_XOR_WriteProcessMemory_9d13 {
  strings:
    $key_9d13 = { ca 61 [2] f8 43 [2] fe 76 [2] d0 76 [2] ef 6a }

  condition:
    any of them
}