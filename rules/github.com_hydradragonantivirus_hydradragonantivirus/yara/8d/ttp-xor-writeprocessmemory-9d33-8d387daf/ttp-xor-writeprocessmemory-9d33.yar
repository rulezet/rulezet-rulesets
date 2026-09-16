rule TTP_XOR_WriteProcessMemory_9d33 {
  strings:
    $key_9d33 = { ca 41 [2] f8 63 [2] fe 56 [2] d0 56 [2] ef 4a }

  condition:
    any of them
}