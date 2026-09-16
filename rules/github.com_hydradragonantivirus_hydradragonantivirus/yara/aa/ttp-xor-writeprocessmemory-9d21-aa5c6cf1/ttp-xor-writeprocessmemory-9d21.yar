rule TTP_XOR_WriteProcessMemory_9d21 {
  strings:
    $key_9d21 = { ca 53 [2] f8 71 [2] fe 44 [2] d0 44 [2] ef 58 }

  condition:
    any of them
}