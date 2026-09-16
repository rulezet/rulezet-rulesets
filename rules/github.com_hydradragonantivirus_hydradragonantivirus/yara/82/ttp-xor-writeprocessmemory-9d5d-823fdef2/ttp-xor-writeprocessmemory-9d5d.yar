rule TTP_XOR_WriteProcessMemory_9d5d {
  strings:
    $key_9d5d = { ca 2f [2] f8 0d [2] fe 38 [2] d0 38 [2] ef 24 }

  condition:
    any of them
}