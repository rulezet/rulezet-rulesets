rule TTP_XOR_WriteProcessMemory_9d6c {
  strings:
    $key_9d6c = { ca 1e [2] f8 3c [2] fe 09 [2] d0 09 [2] ef 15 }

  condition:
    any of them
}