rule TTP_XOR_WriteProcessMemory_9de0 {
  strings:
    $key_9de0 = { ca 92 [2] f8 b0 [2] fe 85 [2] d0 85 [2] ef 99 }

  condition:
    any of them
}