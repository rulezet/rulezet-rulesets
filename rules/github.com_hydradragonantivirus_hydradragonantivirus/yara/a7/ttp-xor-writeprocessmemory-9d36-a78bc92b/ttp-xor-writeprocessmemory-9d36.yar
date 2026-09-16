rule TTP_XOR_WriteProcessMemory_9d36 {
  strings:
    $key_9d36 = { ca 44 [2] f8 66 [2] fe 53 [2] d0 53 [2] ef 4f }

  condition:
    any of them
}