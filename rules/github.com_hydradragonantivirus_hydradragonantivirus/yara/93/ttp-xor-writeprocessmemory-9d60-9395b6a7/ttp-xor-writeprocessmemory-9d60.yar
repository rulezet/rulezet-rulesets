rule TTP_XOR_WriteProcessMemory_9d60 {
  strings:
    $key_9d60 = { ca 12 [2] f8 30 [2] fe 05 [2] d0 05 [2] ef 19 }

  condition:
    any of them
}