rule TTP_XOR_WriteProcessMemory_9d03 {
  strings:
    $key_9d03 = { ca 71 [2] f8 53 [2] fe 66 [2] d0 66 [2] ef 7a }

  condition:
    any of them
}