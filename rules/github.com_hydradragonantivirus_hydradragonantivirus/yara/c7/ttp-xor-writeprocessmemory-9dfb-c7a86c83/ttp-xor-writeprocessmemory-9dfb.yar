rule TTP_XOR_WriteProcessMemory_9dfb {
  strings:
    $key_9dfb = { ca 89 [2] f8 ab [2] fe 9e [2] d0 9e [2] ef 82 }

  condition:
    any of them
}