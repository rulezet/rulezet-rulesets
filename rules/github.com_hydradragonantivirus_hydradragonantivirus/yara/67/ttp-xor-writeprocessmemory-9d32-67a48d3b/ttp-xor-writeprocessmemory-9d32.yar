rule TTP_XOR_WriteProcessMemory_9d32 {
  strings:
    $key_9d32 = { ca 40 [2] f8 62 [2] fe 57 [2] d0 57 [2] ef 4b }

  condition:
    any of them
}