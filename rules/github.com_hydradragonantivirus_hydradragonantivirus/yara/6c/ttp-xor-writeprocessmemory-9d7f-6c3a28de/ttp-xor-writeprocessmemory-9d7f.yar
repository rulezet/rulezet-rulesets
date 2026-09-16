rule TTP_XOR_WriteProcessMemory_9d7f {
  strings:
    $key_9d7f = { ca 0d [2] f8 2f [2] fe 1a [2] d0 1a [2] ef 06 }

  condition:
    any of them
}