rule TTP_XOR_WriteProcessMemory_9de6 {
  strings:
    $key_9de6 = { ca 94 [2] f8 b6 [2] fe 83 [2] d0 83 [2] ef 9f }

  condition:
    any of them
}