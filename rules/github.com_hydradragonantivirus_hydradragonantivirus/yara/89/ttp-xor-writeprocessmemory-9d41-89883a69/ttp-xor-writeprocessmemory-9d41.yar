rule TTP_XOR_WriteProcessMemory_9d41 {
  strings:
    $key_9d41 = { ca 33 [2] f8 11 [2] fe 24 [2] d0 24 [2] ef 38 }

  condition:
    any of them
}