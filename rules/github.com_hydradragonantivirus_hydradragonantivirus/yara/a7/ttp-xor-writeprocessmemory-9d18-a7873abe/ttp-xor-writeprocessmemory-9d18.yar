rule TTP_XOR_WriteProcessMemory_9d18 {
  strings:
    $key_9d18 = { ca 6a [2] f8 48 [2] fe 7d [2] d0 7d [2] ef 61 }

  condition:
    any of them
}