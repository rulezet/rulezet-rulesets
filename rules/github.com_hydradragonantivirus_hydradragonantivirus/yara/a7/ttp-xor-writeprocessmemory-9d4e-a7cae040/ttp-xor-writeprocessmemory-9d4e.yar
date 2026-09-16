rule TTP_XOR_WriteProcessMemory_9d4e {
  strings:
    $key_9d4e = { ca 3c [2] f8 1e [2] fe 2b [2] d0 2b [2] ef 37 }

  condition:
    any of them
}