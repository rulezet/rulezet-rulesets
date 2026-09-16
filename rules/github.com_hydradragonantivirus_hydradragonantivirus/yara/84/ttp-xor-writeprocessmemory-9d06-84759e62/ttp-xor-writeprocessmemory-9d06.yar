rule TTP_XOR_WriteProcessMemory_9d06 {
  strings:
    $key_9d06 = { ca 74 [2] f8 56 [2] fe 63 [2] d0 63 [2] ef 7f }

  condition:
    any of them
}