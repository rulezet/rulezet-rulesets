rule TTP_XOR_WriteProcessMemory_9df0 {
  strings:
    $key_9df0 = { ca 82 [2] f8 a0 [2] fe 95 [2] d0 95 [2] ef 89 }

  condition:
    any of them
}