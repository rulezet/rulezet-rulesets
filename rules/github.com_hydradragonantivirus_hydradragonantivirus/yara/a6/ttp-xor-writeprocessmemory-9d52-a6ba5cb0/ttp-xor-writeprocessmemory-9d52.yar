rule TTP_XOR_WriteProcessMemory_9d52 {
  strings:
    $key_9d52 = { ca 20 [2] f8 02 [2] fe 37 [2] d0 37 [2] ef 2b }

  condition:
    any of them
}