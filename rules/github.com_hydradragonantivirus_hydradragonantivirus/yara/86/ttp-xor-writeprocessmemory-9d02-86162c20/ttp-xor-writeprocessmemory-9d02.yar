rule TTP_XOR_WriteProcessMemory_9d02 {
  strings:
    $key_9d02 = { ca 70 [2] f8 52 [2] fe 67 [2] d0 67 [2] ef 7b }

  condition:
    any of them
}