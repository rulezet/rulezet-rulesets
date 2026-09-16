rule TTP_XOR_WriteProcessMemory_9d66 {
  strings:
    $key_9d66 = { ca 14 [2] f8 36 [2] fe 03 [2] d0 03 [2] ef 1f }

  condition:
    any of them
}