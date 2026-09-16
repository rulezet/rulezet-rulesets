rule TTP_XOR_WriteProcessMemory_9d62 {
  strings:
    $key_9d62 = { ca 10 [2] f8 32 [2] fe 07 [2] d0 07 [2] ef 1b }

  condition:
    any of them
}