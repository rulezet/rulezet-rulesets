rule TTP_XOR_WriteProcessMemory_9d65 {
  strings:
    $key_9d65 = { ca 17 [2] f8 35 [2] fe 00 [2] d0 00 [2] ef 1c }

  condition:
    any of them
}