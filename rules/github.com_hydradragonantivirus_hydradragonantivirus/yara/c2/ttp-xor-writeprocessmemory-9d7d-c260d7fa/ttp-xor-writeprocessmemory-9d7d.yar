rule TTP_XOR_WriteProcessMemory_9d7d {
  strings:
    $key_9d7d = { ca 0f [2] f8 2d [2] fe 18 [2] d0 18 [2] ef 04 }

  condition:
    any of them
}