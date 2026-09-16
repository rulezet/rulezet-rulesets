rule TTP_XOR_WriteProcessMemory_9d67 {
  strings:
    $key_9d67 = { ca 15 [2] f8 37 [2] fe 02 [2] d0 02 [2] ef 1e }

  condition:
    any of them
}