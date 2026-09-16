rule TTP_XOR_WriteProcessMemory_9de2 {
  strings:
    $key_9de2 = { ca 90 [2] f8 b2 [2] fe 87 [2] d0 87 [2] ef 9b }

  condition:
    any of them
}