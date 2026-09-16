rule TTP_XOR_WriteProcessMemory_9d0b {
  strings:
    $key_9d0b = { ca 79 [2] f8 5b [2] fe 6e [2] d0 6e [2] ef 72 }

  condition:
    any of them
}